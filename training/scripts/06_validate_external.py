"""
06_validate_external.py
-----------------------
Applies every trained model to TRUSTLab and compares against the published
baseline. This is the result the study rests on.

WHY THE COMPARISON IS FAIR
Villafranca et al. (2026) reported 0.8963 accuracy on TRUSTLab using DNN
experts pre-trained on CICIDS2017, UNSW-NB15, BoT-IoT and IoTID20 -- that is,
cross-dataset transfer INTO TRUSTLab. This experiment does the same thing
with CICIDS2018 and TII-SSRC-23 as the sources. Same protocol shape,
different source data.

That equivalence is what makes the comparison meaningful. A model trained
natively on TRUSTLab and compared against their 0.8963 would not be a fair
contest, because native training is expected to win.

WHAT TO WATCH
  benign recall     the most diagnostic single number. The training data is
                    attack-heavy, so a model that never learned what normal
                    traffic looks like will show high attack recall and poor
                    benign recall -- and aggregate accuracy hides that.
  per-class table   shows which attack families transfer and which do not.
                    Uniform failure and selective failure mean different
                    things.
  prevalence        the test set caps every class equally, so it is ~6%
                    benign where the corpus is ~57%. Accuracy, precision, F1
                    and F2 all move with that, so every one of them is
                    reported twice: once on the capped set and once reweighted
                    to the corpus's prevalence. Only the reweighted table may
                    be compared with the published figures. Recalls, false
                    alarm rate and ROC-AUC are prevalence-invariant and are
                    the same in both.
  threshold         scoring defaults to 0.445, the operating point the
                    baseline was measured at, so the delta against their
                    figure reflects the model rather than a difference in
                    operating point. --threshold-sweep shows the trade-off
                    across the range, including 0.5.

A LOW SCORE IS A RESULT, NOT A FAILURE. Report it.

Usage:
  python scripts/06_validate_external.py
  python scripts/06_validate_external.py --threshold-sweep
  python scripts/06_validate_external.py --threshold 0.5
  python scripts/06_validate_external.py --harmonise                  # sensitivity run
  python scripts/06_validate_external.py --harmonise --timeout-subset

--harmonise applies src/harmonise.py to the TRUSTLab test features before
scoring (features constant in an arm's training data are set to that value;
negative values in features never negative in training are set to 0).
--timeout-subset also keeps only TRUSTLab flows of at most 120 s, the
public datasets' flow timeout. Both write to results/harmonised/<variant>/
and leave the main results untouched.
"""
import sys
import json
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR,
                             TRUSTLAB_BASELINE, TRAINING_ARMS)
from src.common import get_logger, banner, clean_features, save_json, human
from src.models import build, device
from src.metrics import (binary_metrics, compare_to_baseline, report_text,
                         threshold_sweep, per_class_accuracy)

log = get_logger("06_validate")

ap = argparse.ArgumentParser()
ap.add_argument("--threshold-sweep", action="store_true")
# Defaults to 0.445, not 0.5, because that is the operating point the figures
# in TRUSTLAB_BASELINE were measured at. Scoring at 0.5 and then printing a
# delta against a 0.445 baseline compares two different operating points and
# charges the difference to the model. Script 12 already defaults to 0.445;
# this keeps both scripts describing the same detector the same way.
# Internal validation in script 05 stays at 0.5 on purpose -- it never
# compares against the baseline, so the paper's operating point is irrelevant
# there.
ap.add_argument("--threshold", type=float,
                default=TRUSTLAB_BASELINE["threshold"],
                help="decision threshold (default: the baseline's 0.445)")
ap.add_argument("--harmonise", action="store_true",
                help="harmonise the test features first (src/harmonise.py); "
                     "writes to results/harmonised/")
ap.add_argument("--timeout-subset", action="store_true",
                help="with --harmonise: only TRUSTLab flows of at most 120 s")
args = ap.parse_args()
if args.timeout_subset and not args.harmonise:
    ap.error("--timeout-subset needs --harmonise")
VARIANT = ("fixes_120s" if args.timeout_subset else "fixes") if args.harmonise else None
OUT_PARTS = ("harmonised", VARIANT) if VARIANT else ()

test_path = PROCESSED_DIR / "test_trustlab.parquet"
if not test_path.exists():
    log.error(f"Missing {test_path} -- run 04_align_and_build.py first.")
    sys.exit(1)

feats = joblib.load(ARTIFACTS_DIR / "shared_features.pkl")
tlb = pd.read_parquet(test_path)

if args.timeout_subset:
    from src.harmonise import timeout_mask
    keep = timeout_mask(tlb)
    log.info(f"Timeout-matched subset: {int(keep.sum()):,} of {len(tlb):,} TRUSTLab "
             f"flows end within 120 s")
    tlb = tlb[keep].reset_index(drop=True)
X_clean = clean_features(tlb, feats)
X_raw = X_clean.values
y = tlb["binary_label"].values.astype(int)
cls = tlb["folder_class"].values

# TRUSTLab's real class prevalence, written by script 03. The test set caps
# every class equally, so it is ~6% benign while the corpus is ~57% benign --
# and accuracy, F1, F2 and precision all move with prevalence. The published
# 0.8963 was measured on the real distribution, so comparing a capped-set
# accuracy against it compares two different populations. Reweighting the
# per-class accuracies to the native counts gives a figure that is actually
# comparable, without resampling anything.
NATIVE, TRUNCATED = None, []
_np = ARTIFACTS_DIR / "trustlab_native_counts.json"
if _np.exists():
    _nd = json.load(open(_np, encoding="utf-8"))
    NATIVE, TRUNCATED = _nd["counts"], _nd.get("truncated", [])
    if args.timeout_subset:
        # A class with no flow under 120 s cannot be reweighted; the others
        # keep their corpus counts, so the subset is read at native prevalence.
        _present = set(pd.Series(cls).unique())
        NATIVE = {c: n for c, n in NATIVE.items() if c in _present}

# Per-row weights that carry the capped test set to the corpus's prevalence:
# a row of class c stands for NATIVE[c] / (rows of c in the test set) rows of
# the real population. Every metric computed with these is measured on the
# population the published figures were measured on -- not accuracy alone.
# Accuracy is the only one that can be recovered from per-class accuracies;
# precision, F1 and F2 need the confusion matrix, which is why the weights
# exist rather than a second reweighting formula.
W_NATIVE, W_EXCL = None, None
if NATIVE:
    _nc = pd.Series(cls).value_counts()
    if set(_nc.index) != set(NATIVE):
        log.warning("Native reweighting skipped: the test set's classes do "
                    "not match the corpus counts in "
                    "trustlab_native_counts.json.")
    else:
        _scale = {c: NATIVE[c] / int(_nc[c]) for c in NATIVE}
        W_NATIVE = pd.Series(cls).map(_scale).to_numpy(float)
        if TRUNCATED:
            # Same weights with the truncated archives' classes zeroed out --
            # a leave-one-class-out, not a separate scoring path.
            _scale_ex = {c: (0.0 if c in TRUNCATED else w)
                         for c, w in _scale.items()}
            W_EXCL = pd.Series(cls).map(_scale_ex).to_numpy(float)

banner(log, "TRUSTLAB TEST SET")
log.info(f"Rows     {human(len(y))}")
log.info(f"Benign   {human(int((y == 0).sum()))}")
log.info(f"Attack   {human(int((y == 1).sum()))}")
log.info(f"Features {len(feats)}")
log.info(f"Threshold {args.threshold}"
         + ("   (the baseline's operating point)"
            if abs(args.threshold - TRUSTLAB_BASELINE["threshold"]) < 1e-9
            else f"   (the baseline used "
                 f"{TRUSTLAB_BASELINE['threshold']}; deltas below are not "
                 f"like-for-like)"))

banner(log, "PUBLISHED BASELINE")
log.info(TRUSTLAB_BASELINE["source"])
log.info("")
log.info(TRUSTLAB_BASELINE["protocol_note"])
log.info("")
for k in ("accuracy", "f2", "roc_auc", "attack_recall", "benign_recall"):
    log.info(f"  {k:<16} {TRUSTLAB_BASELINE[k]:.4f}")
log.info(f"  {'threshold':<16} {TRUSTLAB_BASELINE['threshold']}")

rows = []
# Only the binary training arms. artifacts/ also holds mc_<strategy>/ from
# script 09, which has a scaler.pkl of its own -- and a sixteen-class model
# whose predict_proba(...)[:, 1] is the probability of *Benign*, not of
# attack. Scored as a binary detector it produces a plausible-looking number
# that is meaningless, and writes itself into this table as an arm that was
# never trained here. Matching against TRAINING_ARMS keeps the two
# experiments' artifacts apart.
arms = [ARTIFACTS_DIR / a for a in TRAINING_ARMS]
for arm_dir in sorted(d for d in arms if d.is_dir()):
    scaler_p = arm_dir / "scaler.pkl"
    if not scaler_p.exists():
        continue
    arm = arm_dir.name
    # X_raw was built from shared_features.pkl. Models consume feature
    # vectors positionally, so an arm trained on a different list or a
    # different order would be scored on silently misaligned columns rather
    # than raising anything.
    arm_feats = list(joblib.load(arm_dir / "features.pkl"))
    if arm_feats != list(feats):
        log.error(f"  {arm}: its features.pkl differs from "
                  f"shared_features.pkl -- re-run 04 and 05. Skipped.")
        continue
    scaler = joblib.load(scaler_p)
    if args.harmonise:
        from src.harmonise import training_profile, harmonise, describe
        train_p = PROCESSED_DIR / f"train_{arm}.parquet"
        profile = training_profile(clean_features(pd.read_parquet(train_p, columns=feats), feats))
        X_h, changed = harmonise(X_clean, profile)
        for line in describe(changed):
            log.info(f"  {arm} harmonised: {line}")
        Xs = scaler.transform(X_h.values)
    else:
        Xs = scaler.transform(X_raw)        # transform only, never refit

    banner(log, f"ARM: {arm}")

    for f in sorted(arm_dir.iterdir()):
        if f.name in ("scaler.pkl", "features.pkl",
                      "label_encoder.pkl"):
            continue
        # A ".ckpt.pt" is an in-flight training checkpoint, not a model:
        # its suffix is ".pt" but its stem is "<name>.ckpt", which build()
        # does not know. Left in, it costs the real model a row in the
        # results table and says so only in a log line.
        if f.suffix not in (".pkl", ".pt") or f.name.endswith(".ckpt.pt"):
            continue

        name = f.stem
        try:
            if f.suffix == ".pt":
                m = build(name, Xs.shape[1])
                m.load_state_dict(torch.load(f, map_location=device()))
                m.eval()
                outs = []
                with torch.no_grad():
                    for i in range(0, len(Xs), 8192):
                        xb = torch.tensor(Xs[i:i + 8192]).to(device())
                        outs.append(torch.softmax(m(xb), 1).cpu().numpy())
                score = np.vstack(outs)[:, 1]
            else:
                m = joblib.load(f)
                score = m.predict_proba(Xs)[:, 1]
        except Exception as e:
            log.error(f"  {name}: could not load or predict -- {e}")
            continue

        pred = (score >= args.threshold).astype(int)
        mt = binary_metrics(y, pred, score)
        delta = compare_to_baseline(mt, TRUSTLAB_BASELINE)
        # The same predictions scored at the corpus's prevalence. ROC-AUC is
        # rank-based and prevalence-invariant, so it is the one figure that
        # is comparable in both tables.
        mt_nat = (binary_metrics(y, pred, score, sample_weight=W_NATIVE)
                  if W_NATIVE is not None else None)
        delta_nat = (compare_to_baseline(mt_nat, TRUSTLAB_BASELINE)
                     if mt_nat else None)

        log.info(f"\n  {name}")
        log.info("    on the capped test set (~6% benign; accuracy, "
                 "precision, F1 and F2 here are NOT comparable with the "
                 "published figures):")
        log.info(f"      accuracy       {mt['accuracy']:.4f}")
        log.info(f"      F1             {mt['f1']:.4f}")
        log.info(f"      F2             {mt['f2']:.4f}")
        if mt.get("roc_auc") is not None:
            log.info(f"      ROC-AUC        {mt['roc_auc']:.4f}    "
                     f"baseline {TRUSTLAB_BASELINE['roc_auc']:.4f}   "
                     f"({delta.get('roc_auc', 0):+.4f})   "
                     f"<-- prevalence-invariant, comparable")
        log.info(f"      attack recall  {mt['attack_recall']:.4f}    "
                 f"baseline {TRUSTLAB_BASELINE['attack_recall']:.4f}   "
                 f"({delta.get('attack_recall', 0):+.4f})")
        log.info(f"      benign recall  {mt['benign_recall']:.4f}    "
                 f"baseline {TRUSTLAB_BASELINE['benign_recall']:.4f}   "
                 f"({delta.get('benign_recall', 0):+.4f})   <-- watch")
        log.info(f"      false alarms   {mt['false_alarm_rate']:.4f}")

        c = mt["confusion"]
        log.info(f"    confusion: TN {human(c['tn'])}  FP {human(c['fp'])}  "
                 f"FN {human(c['fn'])}  TP {human(c['tp'])}")

        if mt["benign_recall"] < 0.30:
            log.warning("    Benign recall under 0.30: the model flags most "
                        "normal traffic as attack. Consistent with an "
                        "attack-heavy training distribution.")
        if mt["attack_recall"] < 0.30:
            log.warning("    Attack recall under 0.30: the model misses most "
                        "attacks entirely on unseen traffic.")

        pc = per_class_accuracy(y, pred, cls)
        log.info("    per class:")
        for c_, v in sorted(pc.items(), key=lambda kv: -kv[1]["accuracy"]):
            log.info(f"        {c_:<16} {v['accuracy']:.4f}  "
                     f"(n={human(v['n'])})")

        rew = None
        if mt_nat is not None:
            rew = mt_nat["accuracy"]
            log.info("    at TRUSTLab's native prevalence "
                     "(~57% benign) -- the comparable table:")
            for k_, lbl in (("accuracy", "accuracy"), ("f1", "F1"),
                            ("f2", "F2"), ("precision", "attack precision")):
                base = TRUSTLAB_BASELINE.get(
                    "attack_precision" if k_ == "precision" else k_)
                log.info(f"      {lbl:<16} {mt_nat[k_]:.4f}"
                         + (f"    baseline {base:.4f}   "
                            f"({mt_nat[k_] - base:+.4f})" if base else ""))
            cn = mt_nat["confusion"]
            log.info(f"      confusion (effective rows): TN {human(cn['tn'])}  "
                     f"FP {human(cn['fp'])}  FN {human(cn['fn'])}  "
                     f"TP {human(cn['tp'])}")

        # Leave-one-class-out over the truncated archives. Those classes are
        # sampled from an incomplete file, so the honest question is whether
        # they carry the result. Recomputing without them each run turns that
        # from an assertion in the write-up into a number a reader can check.
        mt_ex, rew_ex = None, None
        if W_EXCL is not None:
            mt_ex = binary_metrics(y, pred, score, sample_weight=W_EXCL)
            rew_ex = mt_ex["accuracy"]
            log.info(f"      excluding truncated {TRUNCATED}: accuracy "
                     f"{rew_ex:.4f} (moves {rew_ex - rew:+.4f}), F2 "
                     f"{mt_ex['f2']:.4f} (moves {mt_ex['f2'] - mt_nat['f2']:+.4f})")

        payload = {"arm": arm, "model": name,
                   "threshold": args.threshold,
                   "accuracy_native_prevalence": rew,
                   "accuracy_native_excluding_truncated": rew_ex,
                   "truncated_classes": TRUNCATED,
                   "external_validation": mt,
                   "external_validation_native_prevalence": mt_nat,
                   "external_validation_native_excluding_truncated": mt_ex,
                   "baseline": TRUSTLAB_BASELINE,
                   "delta_vs_baseline": delta,
                   "delta_vs_baseline_native_prevalence": delta_nat,
                   "per_class_accuracy": pc}

        if args.threshold_sweep:
            sweep = threshold_sweep(y, score)
            payload["threshold_sweep"] = sweep
            log.info("    threshold sweep:")
            for r in sweep:
                mark = "  <- baseline used this" \
                    if abs(r["threshold"] - TRUSTLAB_BASELINE["threshold"]) < 1e-6 else ""
                log.info(f"        t={r['threshold']:.3f}  "
                         f"acc {r['accuracy']:.4f}  f2 {r['f2']:.4f}  "
                         f"benign {r['benign_recall']:.4f}  "
                         f"attack {r['attack_recall']:.4f}{mark}")

        if args.harmonise:
            payload["harmonised"] = {"variant": VARIANT, "changed": changed,
                                     "rows": int(len(y))}
        save_json(payload, *OUT_PARTS, "external", f"{arm}__{name}.json")
        rows.append({"arm": arm, "model": name,
                     "threshold": args.threshold,
                     "acc_native_prevalence": rew,
                     "f1_native_prevalence": mt_nat["f1"] if mt_nat else None,
                     "f2_native_prevalence": mt_nat["f2"] if mt_nat else None,
                     "accuracy": mt["accuracy"], "f1": mt["f1"],
                     "f2": mt["f2"], "roc_auc": mt.get("roc_auc"),
                     "attack_recall": mt["attack_recall"],
                     "benign_recall": mt["benign_recall"],
                     # Against the published accuracy, at the prevalence it
                     # was measured at where that is available.
                     "vs_baseline": ((delta_nat or delta).get("accuracy"))})

banner(log, "SUMMARY")
if not rows:
    log.error("No models evaluated. Run 05_train_binary.py first.")
    sys.exit(1)

df = pd.DataFrame(rows)
# Rank on the reweighted figure where it exists. Ranking on the capped-set
# accuracy rewards whichever model says "attack" most often, because that test
# set is 94% attack -- it puts the arm trained on 1,301 benign rows at the top
# of the table, while the same model sits near the bottom once the population
# is corrected.
rank_on = ("acc_native_prevalence"
           if "acc_native_prevalence" in df
           and df["acc_native_prevalence"].notna().all() else "accuracy")
df = df.sort_values(rank_on, ascending=False)
log.info("\n" + df.to_string(index=False))
RESULTS_DIR.joinpath(*OUT_PARTS).mkdir(parents=True, exist_ok=True)
df.to_csv(RESULTS_DIR.joinpath(*OUT_PARTS, "external_validation.csv"), index=False)

best = df.iloc[0]
if rank_on == "acc_native_prevalence":
    log.info("\nRanked by accuracy at TRUSTLab's native prevalence -- the only "
             "column comparable with the published figure.")
    log.info(f"Best: {best['model']} ({best['arm']}) -- "
             f"{best[rank_on]:.4f} at native prevalence, "
             f"{best['accuracy']:.4f} on the capped test set")
else:
    log.warning("\nRanked on the capped test set, which is ~6% benign against "
                "the corpus's ~57%. NOT comparable with the published figure. "
                "Run script 03 to write "
                "artifacts/trustlab_native_counts.json, then re-run this.")
    log.info(f"Best: {best['model']} ({best['arm']}) -- "
             f"accuracy {best['accuracy']:.4f}")
log.info(f"Published baseline:      {TRUSTLAB_BASELINE['accuracy']:.4f}")
log.info(f"Difference:              "
         f"{best[rank_on] - TRUSTLAB_BASELINE['accuracy']:+.4f}"
         + ("" if rank_on == "acc_native_prevalence"
            else "   (different populations -- not a like-for-like gap)"))

log.info("")
log.info("For the write-up:")
log.info("  * Both figures are cross-dataset transfer into TRUSTLab, so the "
         "protocol is comparable.")
log.info("  * The source datasets differ, so any gap reflects the source "
         "data as much as the architecture. Do not attribute it to the model "
         "alone.")
log.info("  * Compare arms: if cicids_only performs close to combined, "
         "TII-SSRC-23 added little. If tii_only collapses, that evidences "
         "why combining was necessary.")

banner(log, "NEXT")
log.info("python scripts/07_aggregate_results.py")
