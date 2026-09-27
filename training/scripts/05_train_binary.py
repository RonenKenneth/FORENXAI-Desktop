"""
05_train_binary.py
------------------
Trains the five binary classifiers on one training arm.

MODELS
  MLP          dense feedforward, makes no ordering assumption
  CNN1D        Hossain's best-performing architecture
  LSTM         sequence model; the plausible advantage on low-and-slow attacks
  CNN_BiLSTM   convolutional front-end into a bidirectional LSTM
  XGBoost      non-deep control -- TRUSTLab's own baseline used XGBoost

SCALING
StandardScaler is fitted on the training split ONLY, then applied unchanged
to the internal validation split and later to TRUSTLab. Fitting it on data
the model will be evaluated on would leak distribution information and
inflate the result. The fitted scaler is saved alongside the models because
inference needs exactly the same transform.

CLASS WEIGHTING
Deep models use weighted cross-entropy; XGBoost uses scale_pos_weight. Both
compensate for residual imbalance in the same way, so the comparison between
model families stays fair.

WHAT THE NUMBERS HERE MEAN
These are on a held-out split of the TRAINING data -- the same capture
environments the model learned from. They will look good. They are not the
result of interest. Script 06 produces the number that matters.

Usage:
  python scripts/05_train_binary.py --arm combined
  python scripts/05_train_binary.py --arm combined --models MLP CNN1D
  python scripts/05_train_binary.py --all-arms
  python scripts/05_train_binary.py --all-arms --resume   # after an interruption
"""
import sys
import time
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, SEED, ALL_MODELS,
                             EPOCHS, BATCH_SIZE, LEARNING_RATE,
                             EARLY_STOP_PATIENCE, VAL_FRACTION, TRAINING_ARMS,
                             LEAKAGE_SAFE_SPLITS)
from src.common import (get_logger, banner, set_seed, clean_features,
                        save_json, load_json, human, feature_ids,
                        group_split, check_no_leakage)
from src.models import (build, build_xgboost, device, count_parameters,
                        free_gpu)
from src.metrics import binary_metrics, report_text

log = get_logger("05_train")
set_seed()

ap = argparse.ArgumentParser()
ap.add_argument("--arm", choices=TRAINING_ARMS, default="combined")
ap.add_argument("--all-arms", action="store_true")
ap.add_argument("--models", nargs="+", default=ALL_MODELS)
# A full sweep is five models across three arms and runs for hours on CPU.
# Each model is written the moment it finishes, so an interruption only costs
# the one in flight -- but without --resume the next run retrains everything
# that already succeeded.
#
# Off by default on purpose: a silently kept model is worse than a slow rerun.
# Change a hyperparameter and an always-on resume would hand back stale
# artifacts that no longer match the config. Ask for it, and use --force to
# retrain over the top.
ap.add_argument("--resume", action="store_true",
                help="skip models already present in artifacts/<arm>/")
ap.add_argument("--force", action="store_true",
                help="retrain even when the model file exists")
args = ap.parse_args()

arms = TRAINING_ARMS if args.all_arms else [args.arm]
feats = joblib.load(ARTIFACTS_DIR / "shared_features.pkl")

log.info(f"Features : {len(feats)}")
log.info(f"Arms     : {arms}")
log.info(f"Models   : {args.models}")
log.info(f"Device   : {device()}")


def train_torch(name, Xtr, ytr, Xva, yva, ckpt=None, resume=False):
    """Training loop with weighted loss and early stopping on validation loss."""
    dev = device()
    model = build(name, Xtr.shape[1])
    log.info(f"    parameters: {human(count_parameters(model))}")

    counts = np.bincount(ytr, minlength=2).astype(float)
    weights = counts.sum() / (2.0 * np.maximum(counts, 1))
    log.info(f"    class weights: benign {weights[0]:.3f}, "
             f"attack {weights[1]:.3f}")
    crit = nn.CrossEntropyLoss(
        weight=torch.tensor(weights, dtype=torch.float32, device=dev))
    opt = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    tr = DataLoader(TensorDataset(torch.tensor(Xtr),
                                  torch.tensor(ytr, dtype=torch.long)),
                    batch_size=BATCH_SIZE, shuffle=True)
    va = DataLoader(TensorDataset(torch.tensor(Xva),
                                  torch.tensor(yva, dtype=torch.long)),
                    batch_size=BATCH_SIZE)

    start_ep, best, wait, best_state = 0, np.inf, 0, None
    # Resume a model that was interrupted mid-training. Optimizer moments and
    # the RNG state are restored alongside the weights, because Adam without
    # its moments restarts the step-size adaptation and a fresh RNG reshuffles
    # the batches -- either one makes the continuation a different run rather
    # than the same run carried on.
    if resume and ckpt is not None and ckpt.exists():
        st = torch.load(ckpt, map_location=dev, weights_only=False)
        model.load_state_dict(st["model"])
        opt.load_state_dict(st["opt"])
        torch.set_rng_state(st["rng"])
        best, wait, start_ep, best_state = (st["best"], st["wait"],
                                            st["epoch"], st["best_state"])
        log.info(f"    resumed at epoch {start_ep + 1}/{EPOCHS} "
                 f"(best val loss so far {best:.4f})")

    for ep in range(start_ep, EPOCHS):
        model.train()
        tl = 0.0
        for xb, yb in tr:
            xb, yb = xb.to(dev), yb.to(dev)
            opt.zero_grad()
            loss = crit(model(xb), yb)
            loss.backward()
            opt.step()
            tl += loss.item() * len(xb)
        tl /= len(tr.dataset)

        model.eval()
        vl = 0.0
        with torch.no_grad():
            for xb, yb in va:
                xb, yb = xb.to(dev), yb.to(dev)
                vl += crit(model(xb), yb).item() * len(xb)
        vl /= len(va.dataset)

        if ep % 5 == 0 or ep == EPOCHS - 1:
            log.info(f"    epoch {ep+1:>3}/{EPOCHS}  train {tl:.4f}  val {vl:.4f}")

        if vl < best - 1e-4:
            best, wait = vl, 0
            best_state = {k: v.detach().cpu().clone()
                          for k, v in model.state_dict().items()}
        else:
            wait += 1
            if wait >= EARLY_STOP_PATIENCE:
                log.info(f"    early stop at epoch {ep+1} "
                         f"(best val loss {best:.4f})")
                break

        # Written every epoch, not only on improvement, so `wait` stays
        # truthful -- resuming with a stale patience counter would let a model
        # that had already stopped improving keep going.
        if ckpt is not None:
            torch.save({"model": model.state_dict(), "opt": opt.state_dict(),
                        "rng": torch.get_rng_state(), "best": best,
                        "wait": wait, "epoch": ep + 1,
                        "best_state": best_state}, ckpt)

    if best_state:
        model.load_state_dict(best_state)
    return model


def predict_torch(model, X, batch=8192):
    dev = device()
    model.eval()
    outs = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            xb = torch.tensor(X[i:i + batch]).to(dev)
            outs.append(torch.softmax(model(xb), 1).cpu().numpy())
    p = np.vstack(outs)[:, 1]
    return p, (p >= 0.5).astype(int)


rows = []
for arm in arms:
    path = PROCESSED_DIR / f"train_{arm}.parquet"
    if not path.exists():
        log.error(f"Missing {path} -- run 04_align_and_build.py first.")
        continue

    banner(log, f"ARM: {arm}")
    df = pd.read_parquet(path)
    X = clean_features(df, feats).values
    y = df["binary_label"].values.astype(int)

    nb, na = int((y == 0).sum()), int((y == 1).sum())
    log.info(f"Rows {human(len(y))}   benign {human(nb)}   attack {human(na)}")

    if nb < 1000:
        log.warning("Fewer than 1,000 benign rows. This arm cannot learn a "
                    "useful notion of normal traffic -- expect it to predict "
                    "attack almost unconditionally. That outcome is itself "
                    "informative and should be reported, not hidden.")

    if LEAKAGE_SAFE_SPLITS:
        # Copies of one flow must not straddle the split, or early stopping
        # and the validation score reward memorisation.
        ids = feature_ids(df, feats)
        itr, iva = group_split(y, ids, VAL_FRACTION)
        Xtr, Xva, ytr, yva = X[itr], X[iva], y[itr], y[iva]
        check_no_leakage(ids[itr], ids[iva], log, "train / validation")
    else:
        Xtr, Xva, ytr, yva = train_test_split(
            X, y, test_size=VAL_FRACTION, random_state=SEED, stratify=y)

    scaler = StandardScaler().fit(Xtr)      # TRAIN ONLY
    Xtr_s, Xva_s = scaler.transform(Xtr), scaler.transform(Xva)

    out_dir = ARTIFACTS_DIR / arm
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, out_dir / "scaler.pkl")
    joblib.dump(feats, out_dir / "features.pkl")

    for name in args.models:
        done = next((out_dir / f"{name}{ext}" for ext in (".pkl", ".pt")
                     if (out_dir / f"{name}{ext}").exists()), None)
        if done and done.name.endswith(".ckpt.pt"):
            done = None
        if done and args.resume and not args.force:
            # Re-use the banked metrics, so the summary below lists the whole
            # sweep rather than only the models this invocation happened to
            # train. Script 07 rebuilds its tables from these same JSON files.
            prev = load_json(arm, f"{name}_internal.json")
            if prev:
                pm = prev["internal_validation"]
                rows.append({"arm": arm, "model": name,
                             "acc": pm["accuracy"], "f1": pm["f1"],
                             "f2": pm["f2"],
                             "benign_recall": pm["benign_recall"],
                             "attack_recall": pm["attack_recall"],
                             "seconds": prev.get("train_seconds")})
            log.info(f"\n  --- {name} --- already trained ({done.name}), "
                     f"skipped" + ("" if prev else
                                   "; no banked metrics, run 07 to rebuild"))
            continue

        log.info(f"\n  --- {name} ---")
        t0 = time.time()
        try:
            if name == "XGBoost":
                # Hand the GPU back before XGBoost asks for it. PyTorch's
                # caching allocator keeps every block it has ever used, so
                # after four deep models in this same process the card looks
                # full to anything outside torch and XGBoost crawls: in the
                # 2026-09-21 sweep it took 98.2 s here against 4.0 s when run
                # on its own, and the multiclass control took 2,002.8 s
                # against 77.3 s. Same model, same data -- the fits were
                # byte-identical -- so this cost nothing but wall-clock, and
                # it only showed up because the earlier run trained one model
                # per process. Verified by the fix: 2 s in the same position
                # afterwards.
                #
                # Not to be confused with XGBoost's "mismatched devices"
                # warning, which is a separate and harmless thing: the
                # booster is on cuda while the input array is in host memory,
                # so it builds a DMatrix rather than predicting in place.
                # That path is still about six times faster than moving the
                # booster to the CPU, so it is the right one to take.
                free_gpu()
                spw = float((ytr == 0).sum()) / max(1, (ytr == 1).sum())
                log.info(f"    scale_pos_weight: {spw:.3f}")
                m = build_xgboost(scale_pos_weight=spw)
                m.fit(Xtr_s, ytr)
                score = m.predict_proba(Xva_s)[:, 1]
                pred = (score >= 0.5).astype(int)
                joblib.dump(m, out_dir / f"{name}.pkl")
            else:
                ckpt = out_dir / f"{name}.ckpt.pt"
                m = train_torch(name, Xtr_s, ytr, Xva_s, yva,
                                ckpt=ckpt, resume=args.resume)
                score, pred = predict_torch(m, Xva_s)
                torch.save(m.state_dict(), out_dir / f"{name}.pt")
                ckpt.unlink(missing_ok=True)   # the model file supersedes it
        except Exception as e:
            log.error(f"    FAILED: {e}")
            continue

        secs = time.time() - t0
        mt = binary_metrics(yva, pred, score)
        log.info(f"    {secs:>6.0f}s  acc {mt['accuracy']:.4f}  "
                 f"f1 {mt['f1']:.4f}  f2 {mt['f2']:.4f}  "
                 f"benign recall {mt['benign_recall']:.4f}")

        save_json({"arm": arm, "model": name,
                   "train_seconds": round(secs, 1),
                   "n_train": int(len(Xtr)), "n_features": len(feats),
                   "internal_validation": mt},
                  arm, f"{name}_internal.json")
        rows.append({"arm": arm, "model": name,
                     "acc": mt["accuracy"], "f1": mt["f1"], "f2": mt["f2"],
                     "benign_recall": mt["benign_recall"],
                     "attack_recall": mt["attack_recall"],
                     "seconds": round(secs, 1)})

banner(log, "INTERNAL VALIDATION SUMMARY")
if rows:
    s = pd.DataFrame(rows)
    log.info("\n" + s.to_string(index=False))
    s.to_csv(ARTIFACTS_DIR / "internal_validation.csv", index=False)

log.warning("")
log.warning("These figures come from a held-out split of the SAME capture "
            "environments the models trained on. A model can score highly "
            "here and still fail completely on unseen traffic. Script 06 "
            "produces the result the study actually rests on.")

banner(log, "NEXT")
log.info("python scripts/06_validate_external.py")
