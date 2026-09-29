"""
11_session_artifact_test.py
---------------------------
A diagnostic nobody has run on TRUSTLab. It tests whether the design choice
that makes the dataset good also introduces a confound.

THE ISSUE
TRUSTLab's central contribution is its single-class session policy: every
capture window contains only benign traffic or only one attack family, never
both. This eliminates label ambiguity -- no bi-flow can blend benign and
malicious behaviour and then receive a single misleading label.

But the same design means every attack family was captured in its own
isolated window, on its own hardware configuration, at its own time. Any
artifact specific to a session -- a source address range, a clock
characteristic, a tool's default parameter, a link condition -- would
correlate perfectly with the class label.

A model could then learn "this looks like the session where Slowloris was
run" rather than "this looks like Slowloris". That would produce excellent
in-dataset accuracy and no transferable capability at all.

WHAT THE SCRIPT DOES

  Test 1  Trains a classifier to predict the source class from the features,
          using flows from LATE in each capture to predict labels learned
          from EARLY flows. If accuracy is near-perfect even across that
          temporal separation, the signal may be session-level rather than
          behavioural.

  Test 2  Compares random-split against temporal-split accuracy for the same
          model. A large drop under temporal splitting means the model was
          relying on within-session correlation that random splitting hides.

  Test 3  Feature ablation. Removes features most likely to encode capture
          conditions -- TCP initial window size is an OS fingerprint,
          minimum inter-arrival time largely reflects link speed -- and
          measures both the accuracy cost and whether class separability
          survives.

HOW TO READ THE OUTCOME
A large temporal-vs-random gap is evidence of session artifacts. A small gap
means the model generalises across sessions within a class, which supports
the dataset's design. Either result is publishable; the second is arguably
more useful to the field, since it validates a methodology other researchers
might adopt.

Usage:  python scripts/11_session_artifact_test.py
"""
import sys
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR, SEED,
                             MC_HARD_CLASSES)
from src.common import get_logger, banner, clean_features, human
from src.models import device

log = get_logger("11_session")

# This script takes no options. Parsing anyway so that "--help" prints help
# and a mistyped flag is an error, rather than both being ignored and the
# job starting regardless -- which for a stage that rewrites an interim
# parquet at the end means a long accidental run.
argparse.ArgumentParser(
    description="Test whether the multiclass result depends on within-session correlation. Takes no options.").parse_args()

import xgboost as xgb
# USE_GPU is a request, not a fact: without CUDA, asking XGBoost for "cuda"
# warns about the device mismatch on every fit and falls back to CPU, and older
# builds raise instead -- which here would take the whole script down rather
# than one model. device() resolves the request against what is installed.
XGB_KW = {"tree_method": "hist"}
if device().type == "cuda":
    XGB_KW["device"] = "cuda"


def quick_model(n_classes):
    """A fast reference model -- this script measures signal, not ceiling."""
    return xgb.XGBClassifier(
        n_estimators=150, max_depth=8, learning_rate=0.1,
        objective="multi:softprob", num_class=n_classes,
        eval_metric="mlogloss", random_state=SEED, n_jobs=-1, **XGB_KW)


feats = joblib.load(ARTIFACTS_DIR / "mc_features.pkl")
out = {"tests": {}}

# --------------------------------------------------------------------------
banner(log, "TEST 1 & 2 -- RANDOM vs TEMPORAL SPLIT")
log.info("Same model, same data, two ways of dividing it. The difference "
         "measures how much the model depends on within-session correlation.")

results = {}
for strat in ("random", "temporal"):
    tr_p = PROCESSED_DIR / f"mc_train_{strat}.parquet"
    te_p = PROCESSED_DIR / f"mc_test_{strat}.parquet"
    if not tr_p.exists():
        log.warning(f"  {strat}: split not built. Run "
                    f"08_build_multiclass.py --strategy both")
        continue

    tr = pd.read_parquet(tr_p)
    te = pd.read_parquet(te_p)

    le = LabelEncoder().fit(sorted(tr["folder_class"].unique()))
    Xtr = clean_features(tr, feats).values
    Xte = clean_features(te, feats).values
    ytr = le.transform(tr["folder_class"])
    yte = le.transform(te["folder_class"])

    m = quick_model(len(le.classes_))
    m.fit(Xtr, ytr)
    pred = m.predict(Xte)

    acc = accuracy_score(yte, pred)
    macro = f1_score(yte, pred, average="macro", zero_division=0)
    per_class = f1_score(yte, pred, average=None,
                         labels=range(len(le.classes_)), zero_division=0)

    results[strat] = {
        "accuracy": float(acc), "macro_f1": float(macro),
        "per_class_f1": {c: float(per_class[i])
                         for i, c in enumerate(le.classes_)},
    }
    log.info(f"\n  {strat:<10} accuracy {acc:.4f}   macro F1 {macro:.4f}")
    for c in MC_HARD_CLASSES:
        if c in list(le.classes_):
            i = list(le.classes_).index(c)
            log.info(f"      {c:<16} F1 {per_class[i]:.4f}")

if len(results) == 2:
    d_acc = results["random"]["accuracy"] - results["temporal"]["accuracy"]
    d_f1 = results["random"]["macro_f1"] - results["temporal"]["macro_f1"]
    log.info(f"\n  Random minus temporal:  accuracy {d_acc:+.4f}   "
             f"macro F1 {d_f1:+.4f}")

    if d_acc > 0.10:
        log.warning("\n  A drop above 0.10 under temporal splitting suggests "
                    "the model was exploiting within-session correlation. "
                    "Flows from the same capture window resemble each other "
                    "beyond what their class alone explains, and random "
                    "splitting scatters those across train and test.")
        log.warning("  Report the temporal figure as the honest one, and note "
                    "that the published baseline used random splitting.")
    elif d_acc > 0.03:
        log.info("\n  A modest drop. Some session dependence, but the model "
                 "largely generalises across capture windows within a class.")
    else:
        log.info("\n  Little to no drop. The model generalises across "
                 "sessions, which supports TRUSTLab's single-class capture "
                 "design rather than undermining it.")

    log.info("\n  Per-class change (random -> temporal):")
    for c in sorted(results["random"]["per_class_f1"]):
        a = results["random"]["per_class_f1"][c]
        b = results["temporal"]["per_class_f1"].get(c, float("nan"))
        mark = "  <- hard" if c in MC_HARD_CLASSES else ""
        log.info(f"      {c:<18} {a:.4f} -> {b:.4f}  ({b-a:+.4f}){mark}")

    out["tests"]["split_comparison"] = {
        "random": results["random"], "temporal": results["temporal"],
        "accuracy_drop": float(d_acc), "macro_f1_drop": float(d_f1)}
else:
    log.warning("Both splits are needed for this comparison. Run:")
    log.warning("  python scripts/08_build_multiclass.py --strategy both")

# --------------------------------------------------------------------------
banner(log, "TEST 3 -- FEATURE ABLATION")
log.info("Removes features that plausibly encode capture conditions rather "
         "than attack behaviour, and measures what changes.")

CANDIDATES = {
    "FWD Init Win Bytes": "TCP receive buffer set by the sending OS",
    "Bwd Init Win Bytes": "TCP receive buffer set by the receiving OS",
    "Flow IAT Min":       "minimum packet gap, largely a function of link speed",
    "Dst Port":           "which services existed on the capture network",
}

strat = "temporal" if (PROCESSED_DIR / "mc_train_temporal.parquet").exists() \
    else "random"
tr = pd.read_parquet(PROCESSED_DIR / f"mc_train_{strat}.parquet")
te = pd.read_parquet(PROCESSED_DIR / f"mc_test_{strat}.parquet")
le = LabelEncoder().fit(sorted(tr["folder_class"].unique()))
ytr = le.transform(tr["folder_class"])
yte = le.transform(te["folder_class"])
log.info(f"Using the {strat} split.")

present = [f for f in CANDIDATES if f in feats]
log.info(f"Candidates present in the feature set: {present}")
for f in present:
    log.info(f"    {f:<22} {CANDIDATES[f]}")

abl = {}
base_feats = list(feats)
m = quick_model(len(le.classes_))
m.fit(clean_features(tr, base_feats).values, ytr)
pred = m.predict(clean_features(te, base_feats).values)
base_acc = accuracy_score(yte, pred)
base_f1 = f1_score(yte, pred, average="macro", zero_division=0)
log.info(f"\n  baseline ({len(base_feats)} features): "
         f"accuracy {base_acc:.4f}  macro F1 {base_f1:.4f}")
abl["baseline"] = {"n_features": len(base_feats),
                   "accuracy": float(base_acc), "macro_f1": float(base_f1)}

for k in range(1, len(present) + 1):
    drop = present[:k]
    sub = [f for f in base_feats if f not in drop]
    m = quick_model(len(le.classes_))
    m.fit(clean_features(tr, sub).values, ytr)
    pred = m.predict(clean_features(te, sub).values)
    a = accuracy_score(yte, pred)
    f = f1_score(yte, pred, average="macro", zero_division=0)
    log.info(f"  minus {k} ({len(sub)} features): accuracy {a:.4f} "
             f"({a-base_acc:+.4f})  macro F1 {f:.4f} ({f-base_f1:+.4f})")
    log.info(f"      removed: {drop}")
    abl[f"minus_{k}"] = {"removed": drop, "n_features": len(sub),
                         "accuracy": float(a), "macro_f1": float(f),
                         "delta_accuracy": float(a - base_acc),
                         "delta_macro_f1": float(f - base_f1)}

out["tests"]["ablation"] = abl

if present:
    worst = abl[f"minus_{len(present)}"]
    if abs(worst["delta_accuracy"]) < 0.02:
        log.info("\n  Removing every candidate barely changed accuracy. The "
                 "model was not relying on those features, so they are not "
                 "the source of any session signal.")
    else:
        log.info(f"\n  Removing every candidate cost "
                 f"{abs(worst['delta_accuracy']):.4f} accuracy. Those "
                 f"features carry real weight -- whether behavioural or "
                 f"environmental cannot be settled by this test alone. The "
                 f"temporal-split comparison above is the better evidence.")

path = RESULTS_DIR / "session_artifact_analysis.json"
with open(path, "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2)

banner(log, "DONE")
log.info(f"Saved -> {path}")
log.info("")
log.info("For the write-up: whichever way this comes out, it is worth "
         "reporting. A large temporal gap identifies a limitation in a "
         "dataset designed to remove limitations. A small gap validates the "
         "single-class capture methodology, which is useful to anyone "
         "considering adopting it.")
