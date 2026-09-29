"""
09_train_multiclass.py
----------------------
Trains the five architectures for sixteen-class classification on TRUSTLab.

WHAT THIS EXPERIMENT IS ACTUALLY TESTING
Thirteen of the sixteen classes already reach F1 of 0.95 or above in the
published baseline. There is nothing to demonstrate on those. The experiment
lives or dies on three classes:

    Slowloris      F1 0.68   about 28% of it is classified as Benign
    DoS            F1 0.74   confused with DDoS in both directions
    Exploitation   F1 0.92   bleeds into WebBased and BufferOverflow

Report the macro average, but the per-class figures for those three are the
result. A model that lifts the overall macro F1 while leaving Slowloris at
0.68 has not done anything interesting.

WHY THE ARCHITECTURE COMPARISON IS WORTH RUNNING
The TRUSTLab authors used a single XGBoost model and stated their goal was to
characterise the dataset, not to optimise architecture. No architecture
comparison exists on this data at all. Hossain (2025) found a 1D CNN best on
a different IoT dataset, but every class there scored above 0.99 -- so his
result says little about the classes that are actually hard here.

The plausible hypothesis: Slowloris and C2Beaconing are distinguished by
temporal periodicity rather than local feature patterns, which would favour
the LSTM or CNN-BiLSTM over the CNN. If that holds, it is a finding. If it
does not, the negative result is also informative.

CLASS WEIGHTING
Weighted cross-entropy for the deep models, sample weights for XGBoost. Both
compute weights the same way, so the comparison between families stays fair.

Usage:
  python scripts/09_train_multiclass.py
  python scripts/09_train_multiclass.py --strategy temporal
  python scripts/09_train_multiclass.py --models CNN1D LSTM
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
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, SEED, ALL_MODELS,
                             MC_EPOCHS, MC_BATCH_SIZE, MC_LEARNING_RATE,
                             MC_EARLY_STOP_PATIENCE, MC_VAL_FRACTION,
                             MC_SPLIT_STRATEGY, MC_HARD_CLASSES,
                             LEAKAGE_SAFE_SPLITS)
from src.common import (get_logger, banner, set_seed, clean_features,
                        save_json, load_json, human, feature_ids,
                        group_split, check_no_leakage)
from src.models import (build, device, count_parameters,
                        build_xgboost_multiclass, free_gpu)

log = get_logger("09_mc_train")
set_seed()

ap = argparse.ArgumentParser()
ap.add_argument("--strategy", choices=["random", "temporal"],
                default=MC_SPLIT_STRATEGY)
ap.add_argument("--models", nargs="+", default=ALL_MODELS)
# Same contract as script 05: --resume skips finished models and picks a
# half-trained one up at its next epoch; --force retrains regardless. Off by
# default so a hyperparameter change is never silently ignored.
ap.add_argument("--resume", action="store_true",
                help="skip finished models, resume an interrupted one")
ap.add_argument("--force", action="store_true",
                help="retrain even when the model file exists")
args = ap.parse_args()

train_path = PROCESSED_DIR / f"mc_train_{args.strategy}.parquet"
if not train_path.exists():
    log.error(f"Missing {train_path} -- run 08_build_multiclass.py first.")
    sys.exit(1)

feats = joblib.load(ARTIFACTS_DIR / "mc_features.pkl")
classes = joblib.load(ARTIFACTS_DIR / "mc_classes.pkl")

df = pd.read_parquet(train_path)
X = clean_features(df, feats).values
le = LabelEncoder().fit(classes)
y = le.transform(df["folder_class"].values)
n_classes = len(le.classes_)

banner(log, f"MULTICLASS TRAINING -- split: {args.strategy}")
log.info(f"Rows     {human(len(y))}")
log.info(f"Features {len(feats)}")
log.info(f"Classes  {n_classes}")
log.info(f"Device   {device()}")

counts = np.bincount(y, minlength=n_classes)
log.info("\nClass distribution:")
for i, c in enumerate(le.classes_):
    mark = "  <- hard class" if c in MC_HARD_CLASSES else ""
    log.info(f"  {c:<18} {human(int(counts[i])):>9}{mark}")

if LEAKAGE_SAFE_SPLITS:
    # Copies of one flow must not straddle the split, or early stopping and
    # the validation score reward memorisation.
    ids = feature_ids(df, feats)
    itr, iva = group_split(y, ids, MC_VAL_FRACTION)
    Xtr, Xva, ytr, yva = X[itr], X[iva], y[itr], y[iva]
    check_no_leakage(ids[itr], ids[iva], log, "train / validation")
else:
    Xtr, Xva, ytr, yva = train_test_split(
        X, y, test_size=MC_VAL_FRACTION, random_state=SEED, stratify=y)

scaler = StandardScaler().fit(Xtr)     # TRAIN ONLY
Xtr_s, Xva_s = scaler.transform(Xtr), scaler.transform(Xva)

out_dir = ARTIFACTS_DIR / f"mc_{args.strategy}"
out_dir.mkdir(parents=True, exist_ok=True)
joblib.dump(scaler, out_dir / "scaler.pkl")
joblib.dump(le, out_dir / "label_encoder.pkl")
joblib.dump(feats, out_dir / "features.pkl")


def class_weights(y_arr, k):
    c = np.bincount(y_arr, minlength=k).astype(float)
    return c.sum() / (k * np.maximum(c, 1))


def train_torch(name, Xtr, ytr, Xva, yva, k, ckpt=None,
                resume=False):
    dev = device()
    model = build(name, Xtr.shape[1], n_classes=k)
    log.info(f"    parameters: {human(count_parameters(model))}")

    w = torch.tensor(class_weights(ytr, k), dtype=torch.float32, device=dev)
    crit = nn.CrossEntropyLoss(weight=w)
    opt = torch.optim.Adam(model.parameters(), lr=MC_LEARNING_RATE)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(
        opt, mode="min", factor=0.5, patience=3)

    tr = DataLoader(TensorDataset(torch.tensor(Xtr),
                                  torch.tensor(ytr, dtype=torch.long)),
                    batch_size=MC_BATCH_SIZE, shuffle=True)
    va = DataLoader(TensorDataset(torch.tensor(Xva),
                                  torch.tensor(yva, dtype=torch.long)),
                    batch_size=MC_BATCH_SIZE)

    start_ep, best, wait, best_state = 0, np.inf, 0, None
    # Optimizer moments, scheduler state and RNG go with the weights. Adam
    # without its moments restarts step-size adaptation, ReduceLROnPlateau
    # without its counters forgets it had already cut the rate, and a fresh
    # RNG reshuffles the batches -- each one turns a continuation into a
    # different run.
    if resume and ckpt is not None and ckpt.exists():
        st = torch.load(ckpt, map_location=dev, weights_only=False)
        model.load_state_dict(st["model"])
        opt.load_state_dict(st["opt"])
        sched.load_state_dict(st["sched"])
        torch.set_rng_state(st["rng"])
        best, wait, start_ep, best_state = (st["best"], st["wait"],
                                            st["epoch"], st["best_state"])
        log.info(f"    resumed at epoch {start_ep + 1}/{MC_EPOCHS} "
                 f"(best val loss so far {best:.4f})")

    for ep in range(start_ep, MC_EPOCHS):
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
        vl, preds = 0.0, []
        with torch.no_grad():
            for xb, yb in va:
                xb, yb = xb.to(dev), yb.to(dev)
                o = model(xb)
                vl += crit(o, yb).item() * len(xb)
                preds.append(o.argmax(1).cpu().numpy())
        vl /= len(va.dataset)
        mf1 = f1_score(yva, np.concatenate(preds), average="macro",
                       zero_division=0)
        sched.step(vl)

        if ep % 5 == 0 or ep == MC_EPOCHS - 1:
            log.info(f"    epoch {ep+1:>3}/{MC_EPOCHS}  train {tl:.4f}  "
                     f"val {vl:.4f}  macro F1 {mf1:.4f}")

        if vl < best - 1e-4:
            best, wait = vl, 0
            best_state = {k_: v.detach().cpu().clone()
                          for k_, v in model.state_dict().items()}
        else:
            wait += 1
            if wait >= MC_EARLY_STOP_PATIENCE:
                log.info(f"    early stop at epoch {ep+1}")
                break

        # Every epoch, not only on improvement, so the patience counter
        # survives an interruption truthfully.
        if ckpt is not None:
            torch.save({"model": model.state_dict(), "opt": opt.state_dict(),
                        "sched": sched.state_dict(),
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
    p = np.vstack(outs)
    return p, p.argmax(1)


rows = []
for name in args.models:
    done = next((out_dir / f"{name}{ext}" for ext in (".pkl", ".pt")
                 if (out_dir / f"{name}{ext}").exists()
                 and not f"{name}{ext}".endswith(".ckpt.pt")), None)
    if done and args.resume and not args.force:
        log.info(f"\n{name}: already trained ({done.name}), skipped")
        prev = load_json(f"mc_{args.strategy}", f"{name}_internal.json")
        if prev:
            rows.append({"strategy": args.strategy, "model": name,
                         "macro_f1": prev.get("val_macro_f1"),
                         "weighted_f1": prev.get("val_weighted_f1"),
                         "seconds": prev.get("train_seconds")})
        continue

    banner(log, name)
    t0 = time.time()
    try:
        if name == "XGBoost":
            # Give the GPU back first. PyTorch's caching allocator holds every
            # block it has touched, so after the four deep models above it the
            # card is full as far as XGBoost can tell, and this fit takes
            # 2,002.8 s where the same one run on its own takes 77.3 s. The
            # resulting model was byte-identical, so only the clock was
            # affected -- see free_gpu in src/models.py. XGBoost's separate
            # "mismatched devices" warning is unrelated and harmless.
            free_gpu()
            # Shared with script 12 so the standalone run and the
            # Phase-2-protocol run differ only in the data they see.
            m = build_xgboost_multiclass(n_classes)
            w = class_weights(ytr, n_classes)
            m.fit(Xtr_s, ytr, sample_weight=w[ytr])
            proba = m.predict_proba(Xva_s)
            pred = proba.argmax(1)
            joblib.dump(m, out_dir / f"{name}.pkl")
        else:
            ckpt = out_dir / f"{name}.ckpt.pt"
            m = train_torch(name, Xtr_s, ytr, Xva_s, yva, n_classes,
                            ckpt=ckpt, resume=args.resume)
            proba, pred = predict_torch(m, Xva_s)
            torch.save(m.state_dict(), out_dir / f"{name}.pt")
            ckpt.unlink(missing_ok=True)     # the model file supersedes it
    except Exception as e:
        log.error(f"  FAILED: {e}")
        continue

    secs = time.time() - t0
    macro = f1_score(yva, pred, average="macro", zero_division=0)
    weighted = f1_score(yva, pred, average="weighted", zero_division=0)
    per_class = f1_score(yva, pred, average=None, labels=range(n_classes),
                         zero_division=0)

    log.info(f"  {secs:.0f}s  macro F1 {macro:.4f}  weighted F1 {weighted:.4f}")
    log.info("  hard classes on validation:")
    for c in MC_HARD_CLASSES:
        if c in list(le.classes_):
            i = list(le.classes_).index(c)
            log.info(f"      {c:<16} F1 {per_class[i]:.4f}")

    save_json({"strategy": args.strategy, "model": name,
               "train_seconds": round(secs, 1),
               "n_train": int(len(Xtr)), "n_features": len(feats),
               "n_classes": n_classes,
               "val_macro_f1": float(macro),
               "val_weighted_f1": float(weighted),
               "val_per_class_f1": {c: float(per_class[i])
                                    for i, c in enumerate(le.classes_)}},
              f"mc_{args.strategy}", f"{name}_internal.json")

    rows.append({"strategy": args.strategy, "model": name,
                 "macro_f1": round(macro, 4),
                 "weighted_f1": round(weighted, 4),
                 "seconds": round(secs, 1)})

banner(log, "VALIDATION SUMMARY")
if rows:
    s = pd.DataFrame(rows).sort_values("macro_f1", ascending=False)
    log.info("\n" + s.to_string(index=False))
    s.to_csv(ARTIFACTS_DIR / f"mc_validation_{args.strategy}.csv", index=False)

log.warning("")
log.warning("These are validation figures from within the training split. "
            "Script 10 evaluates on the held-out test set and compares "
            "per-class results against the published baseline.")

banner(log, "NEXT")
log.info(f"python scripts/10_evaluate_multiclass.py --strategy {args.strategy}")
