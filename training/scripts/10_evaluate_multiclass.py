"""
10_evaluate_multiclass.py
-------------------------
Evaluates every multiclass model on the held-out test set and compares
per-class results against the published TRUSTLab figures.

AN IMPORTANT CAVEAT ABOUT THE COMPARISON
The published per-class figures come from a Phase-2 refinement stage. Their
pipeline first ran a binary detector, then passed only the flows it flagged
as malicious to an XGBoost multiclass model. So their model never saw the
full class distribution -- it saw a filtered subset, and its "Benign" class
exists to recover false positives from the first stage.

This experiment trains a standalone sixteen-class classifier on all the data.
That is a harder task: no upstream filter has removed the easy benign traffic
first. Their numbers are therefore a reference point, not a target to beat.
State this in the write-up rather than presenting the comparison as
like-for-like.

WHAT TO LOOK AT
Macro F1 is reported, but three classes carry the result:

    Slowloris      baseline F1 0.68
    DoS            baseline F1 0.74
    Exploitation   baseline F1 0.92

Thirteen of sixteen classes already sit at 0.95 or above in the baseline, so
improving the macro average by lifting those is not meaningful. The confusion
matrix matters as much as the metrics -- the authors documented specific
failure patterns, and whether those reproduce is the substantive question.

Usage:
  python scripts/10_evaluate_multiclass.py
  python scripts/10_evaluate_multiclass.py --strategy temporal
"""
import sys
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import torch
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             accuracy_score, confusion_matrix,
                             classification_report)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR, SEED,
                             MC_SPLIT_STRATEGY, MC_HARD_CLASSES,
                             TRUSTLAB_MC_BASELINE, TRUSTLAB_KNOWN_CONFUSIONS)
from src.common import get_logger, banner, clean_features, save_json, human
from src.metrics import per_class_f1_ci
from src.models import build, device

log = get_logger("10_mc_eval")

ap = argparse.ArgumentParser()
ap.add_argument("--strategy", choices=["random", "temporal"],
                default=MC_SPLIT_STRATEGY)
args = ap.parse_args()

test_path = PROCESSED_DIR / f"mc_test_{args.strategy}.parquet"
model_dir = ARTIFACTS_DIR / f"mc_{args.strategy}"
if not test_path.exists() or not model_dir.exists():
    log.error("Run 08_build_multiclass.py and 09_train_multiclass.py first.")
    sys.exit(1)

feats = joblib.load(model_dir / "features.pkl")
scaler = joblib.load(model_dir / "scaler.pkl")
le = joblib.load(model_dir / "label_encoder.pkl")
classes = list(le.classes_)

df = pd.read_parquet(test_path)
X = scaler.transform(clean_features(df, feats).values)
y = le.transform(df["folder_class"].values)

banner(log, f"TEST SET -- split: {args.strategy}")
log.info(f"Rows    {human(len(y))}")
log.info(f"Classes {len(classes)}")
for c, n in df["folder_class"].value_counts().items():
    mark = "  <- hard" if c in MC_HARD_CLASSES else ""
    log.info(f"  {c:<18} {human(n):>9}{mark}")

banner(log, "PUBLISHED BASELINE (for reference)")
log.info("From Villafranca et al. (2026), Table 3. Note this came from a "
         "Phase-2 refinement stage, not a standalone classifier -- see the "
         "header of this script.")
for c in sorted(TRUSTLAB_MC_BASELINE):
    b = TRUSTLAB_MC_BASELINE[c]
    mark = "  <- hard" if c in MC_HARD_CLASSES else ""
    log.info(f"  {c:<18} F1 {b['f1']:.2f}{mark}")

rows, per_class_rows = [], []
for f in sorted(model_dir.iterdir()):
    if f.name in ("scaler.pkl", "label_encoder.pkl", "features.pkl"):
        continue
    # A ".ckpt.pt" is an in-flight training checkpoint, not a model: its
    # suffix is ".pt" but its stem is "<name>.ckpt", which build() does
    # not know. Script 09 runs for hours, so this file is present for
    # most of that window and a mid-run evaluation would quietly drop
    # the model it belongs to.
    if f.suffix not in (".pkl", ".pt") or f.name.endswith(".ckpt.pt"):
        continue

    name = f.stem
    try:
        if f.suffix == ".pt":
            m = build(name, X.shape[1], n_classes=len(classes))
            m.load_state_dict(torch.load(f, map_location=device()))
            m.eval()
            outs = []
            with torch.no_grad():
                for i in range(0, len(X), 8192):
                    xb = torch.tensor(X[i:i + 8192].astype("float32")).to(device())
                    outs.append(torch.softmax(m(xb), 1).cpu().numpy())
            proba = np.vstack(outs)
        else:
            m = joblib.load(f)
            proba = m.predict_proba(X)
        pred = proba.argmax(1)
    except Exception as e:
        log.error(f"  {name}: could not load or predict -- {e}")
        continue

    banner(log, name)
    acc = accuracy_score(y, pred)
    macro = f1_score(y, pred, average="macro", zero_division=0)
    weighted = f1_score(y, pred, average="weighted", zero_division=0)
    # Interval alongside every F1. Here every class has ~16,000 test flows so
    # the intervals are tight, but printing them keeps this table readable on
    # the same terms as script 12's, where support varies enormously.
    ci = per_class_f1_ci(y, pred, len(classes),
                         macro_over=range(len(classes)), seed=SEED)
    mci = ci["macro"] or {}
    log.info(f"accuracy {acc:.4f}   macro F1 {macro:.4f} "
             f"[{mci.get('ci_low', float('nan')):.4f}, "
             f"{mci.get('ci_high', float('nan')):.4f}]   "
             f"weighted F1 {weighted:.4f}")

    p = precision_score(y, pred, average=None, labels=range(len(classes)),
                        zero_division=0)
    r = recall_score(y, pred, average=None, labels=range(len(classes)),
                     zero_division=0)
    f1 = f1_score(y, pred, average=None, labels=range(len(classes)),
                  zero_division=0)

    log.info("\n'ref F1' is the published Phase-2 figure. It is a reference, "
             "NOT a target: their model scored only flows a Phase-1 detector "
             "had already called malicious, this one scores everything. "
             "'diff' subtracts two numbers measured under different "
             "protocols -- do not report it as a win or a loss. Script 12 "
             "runs the matched protocol.")
    log.info(f"\n{'class':<18}{'prec':>8}{'recall':>8}{'F1':>8}"
             f"{'ref F1':>9}{'diff':>9}   support")
    pc = {}
    for i, c in enumerate(classes):
        base = TRUSTLAB_MC_BASELINE.get(c, {}).get("f1")
        d = (f1[i] - base) if base is not None else None
        sup = int((y == i).sum())
        mark = "  <- hard" if c in MC_HARD_CLASSES else ""
        log.info(f"{c:<18}{p[i]:>8.4f}{r[i]:>8.4f}{f1[i]:>8.4f}"
                 f"{(base if base else float('nan')):>9.2f}"
                 f"{(d if d is not None else float('nan')):>+9.4f}"
                 f"   {human(sup):>8}{mark}")
        cinf = ci["per_class"].get(i, {})
        pc[c] = {"precision": float(p[i]), "recall": float(r[i]),
                 "f1": float(f1[i]), "support": sup,
                 "ci_low": cinf.get("ci_low"), "ci_high": cinf.get("ci_high"),
                 "ci_width": cinf.get("ci_width"),
                 "baseline_f1": base, "delta": (float(d) if d is not None else None)}
        per_class_rows.append({"strategy": args.strategy, "model": name,
                               "class": c, "f1": round(float(f1[i]), 4),
                               "baseline_f1": base,
                               "delta": round(float(d), 4) if d is not None else None,
                               "support": sup})

    log.info("\nHard classes:")
    for c in MC_HARD_CLASSES:
        if c in pc:
            v = pc[c]
            # Deliberately not "above/below baseline". These two numbers come
            # from different protocols, so a verdict would be wrong here even
            # when the arithmetic is right.
            where = ("higher than" if v["delta"] and v["delta"] > 0.02
                     else "lower than" if v["delta"] and v["delta"] < -0.02
                     else "close to")
            log.info(f"  {c:<16} F1 {v['f1']:.4f}  ({where} the Phase-2 "
                     f"reference {v['baseline_f1']:.2f}; different protocol)")

    # ---- confusion matrix ----
    cm = confusion_matrix(y, pred, labels=range(len(classes)))
    cm_df = pd.DataFrame(cm, index=[f"true_{c}" for c in classes],
                         columns=[f"pred_{c}" for c in classes])
    # save_json creates this directory, but it runs later in the loop -- so
    # on a first run the confusion matrix would be the first thing written
    # into a directory that does not exist yet.
    cm_dir = RESULTS_DIR / f"mc_{args.strategy}"
    cm_dir.mkdir(parents=True, exist_ok=True)
    cm_df.to_csv(cm_dir / f"{name}_confusion.csv")

    reproduced = []
    log.info("\nLargest off-diagonal confusions:")
    off = []
    for i in range(len(classes)):
        for j in range(len(classes)):
            if i != j and cm[i, j] > 0:
                off.append((classes[i], classes[j], int(cm[i, j]),
                            cm[i, j] / max(1, cm[i].sum())))
    for a, b, n, frac in sorted(off, key=lambda t: -t[2])[:10]:
        log.info(f"  {a:<16} -> {b:<16} {human(n):>8}  "
                 f"({frac*100:5.1f}% of {a})")

    # ---- do the documented confusions reproduce? ----
    # Their counts were measured on their test set, whose per-class support is
    # 1.9x to 2.8x ours. Comparing raw counts across differently sized test
    # sets says nothing, so both sides become a rate -- what share of true
    # class A was predicted as B -- using the support the paper published
    # beside each figure.
    log.info("\nConfusions documented in the paper, as a share of the true "
             "class. Raw counts are not comparable: their test set is larger.")
    log.info(f"  {'confusion':<34}{'theirs':>9}{'ours':>9}{'ratio':>9}")
    for a, b, n_pub, why in TRUSTLAB_KNOWN_CONFUSIONS:
        if a not in classes or b not in classes:
            continue
        i, j = classes.index(a), classes.index(b)
        n_here, sup_here = int(cm[i, j]), int(cm[i].sum())
        r_here = n_here / max(1, sup_here)
        sup_pub = TRUSTLAB_MC_BASELINE.get(a, {}).get("support")
        if not sup_pub:
            log.info(f"  {a + ' -> ' + b:<34}{'n/a':>9}{r_here*100:>8.2f}%"
                     f"      (no published support to normalise by)")
            continue
        r_pub = n_pub / sup_pub
        ratio = (r_here / r_pub) if r_pub else float("inf")
        log.info(f"  {a + ' -> ' + b:<34}{r_pub*100:>8.2f}%"
                 f"{r_here*100:>8.2f}%{ratio:>8.2f}x")
        reproduced.append({"from": a, "to": b, "their_explanation": why,
                           "published_n": n_pub, "published_support": sup_pub,
                           "published_rate": float(r_pub),
                           "our_n": n_here, "our_support": sup_here,
                           "our_rate": float(r_here),
                           "rate_ratio": float(ratio)})
    log.info("  A ratio near 1.0 means the confusion reproduced at the same "
             "rate. Far from 1.0 either way is a finding -- but their Phase-2 "
             "never saw unfiltered benign traffic, so a confusion INTO Benign "
             "is the one most likely to differ for protocol reasons alone.")

    save_json({"strategy": args.strategy, "model": name,
               "accuracy": float(acc), "macro_f1": float(macro),
               "macro_f1_ci": ci["macro"],
               "ci_method": ("nonparametric bootstrap over the test set, "
                             f"{ci['n_boot']} resamples, 95% percentile "
                             "interval"),
               "weighted_f1": float(weighted),
               "per_class": pc,
               "documented_confusions": reproduced,
               "protocol_note": (
                   "'baseline_f1' and the documented confusions come from the "
                   "published Phase-2 refinement stage, which scored only "
                   "flows a Phase-1 detector had already flagged as "
                   "malicious. This model scores the full distribution, so "
                   "the two are not like-for-like. Confusions are compared as "
                   "rates because the test sets differ in size. Script 12 "
                   "runs the matched protocol."),
               "confusion_matrix": {"labels": classes, "matrix": cm.tolist()}},
              f"mc_{args.strategy}", f"{name}_test.json")

    rows.append({"strategy": args.strategy, "model": name,
                 "accuracy": round(acc, 4), "macro_f1": round(macro, 4),
                 "weighted_f1": round(weighted, 4),
                 **{f"F1_{c}": round(float(f1[i]), 4)
                    for i, c in enumerate(classes) if c in MC_HARD_CLASSES}})

banner(log, "SUMMARY")
if not rows:
    log.error("No models evaluated.")
    sys.exit(1)

s = pd.DataFrame(rows).sort_values("macro_f1", ascending=False)
log.info("\n" + s.to_string(index=False))
s.to_csv(RESULTS_DIR / f"mc_summary_{args.strategy}.csv", index=False)

pcdf = pd.DataFrame(per_class_rows)
pcdf.to_csv(RESULTS_DIR / f"mc_per_class_{args.strategy}.csv", index=False)

log.info("")
log.info("Reading these results:")
log.info("  * Macro F1 is dominated by the thirteen easy classes. A gain "
         "there is not the finding.")
log.info("  * Slowloris, DoS and Exploitation are where the headroom is. "
         "Check whether any architecture moves them.")
log.info("  * If the documented confusions reproduce across every "
         "architecture, that supports the authors' conclusion that these are "
         "limits of flow-level features rather than modelling failures -- "
         "and TRUSTLab's clean labels rule out annotation noise as the cause.")

banner(log, "NEXT")
log.info("python scripts/11_session_artifact_test.py")
