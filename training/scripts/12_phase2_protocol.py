"""
12_phase2_protocol.py
---------------------
Replicates the published two-stage protocol, and separates how good the
sixteen-class model is from how good the detector in front of it is.

THE PROBLEM THIS SOLVES
Villafranca et al.'s per-class figures come from a Phase-2 refinement stage:
their pipeline ran a binary detector first and passed only the flows it
flagged as malicious to a sixteen-class model. Script 09 trains a standalone
sixteen-class model on everything, so comparing its per-class F1 against
theirs measures the protocol, not the model.

Putting our own detector in front (--phase1 learned) fixes the SHAPE of the
protocol but introduces a second confound, and it is a large one. Their
Phase-1 reached 0.8963 accuracy on TRUSTLab. Ours passes 27.5% of all flows
and its per-class pass-through ranges from 0.1% (BufferOverflow) to 80.4%
(DoS). Phase 2 then sees a subset that is not merely smaller than theirs but shaped
differently, and any residual per-class gap mixes "our classifier differs"
with "our detector is worse". Those need pulling apart.

THE PHASE-1 LADDER
Three filters, one Phase-2 model, the same splits. The model is built by
src.models.build_xgboost_multiclass -- the same builder script 09 uses -- so
across every rung the only thing that changes is which flows arrive.

  oracle    A perfect detector: every attack passes, no benign does. Phase 2
            sees ideal input, so its scores are the classifier's own ceiling,
            free of any detector error. Benign is absent by construction, so
            this rung is a fifteen-class attack-refinement task.

  matched   A detector at THEIR published operating point. The paper reports
            attack recall 0.9498 and benign recall 0.8229, so this passes
            94.98% of attacks and 17.71% of benign as false positives, drawn
            at random with a fixed seed. Phase 2 then sees a subset
            statistically equivalent to the one their Phase-2 was trained and
            scored on. THIS is the rung to compare against their published
            per-class F1.

  learned   Our actual detector from script 05. The honest end-to-end number
            for this pipeline, confound and all.

WHAT THE LADDER BUYS
    oracle  - matched   the cost of realistic detector error
    matched - learned   the cost of OUR detector being worse than theirs
    matched - published the genuine classifier/data difference, which is the
                        number the comparison was always trying to isolate

READ THIS BEFORE QUOTING ORACLE OR MATCHED NUMBERS
Both are built from ground-truth labels. They are counterfactual controls
that quantify sensitivity to Phase-1 quality; they are NOT achievable
performance and must never be reported as this pipeline's results. Only the
`learned` rung describes a system that could actually run. Label them as
controls in the write-up or they will be misread.

One assumption is worth stating: `matched` spreads Phase-1's errors evenly
across classes, because the paper reports its recall overall and not per
class. A real detector concentrates misses in the classes it finds hard, so
`matched` is a neutral reconstruction of their operating point rather than a
reconstruction of their detector.

Usage:
  python scripts/12_phase2_protocol.py --phase1 all
  python scripts/12_phase2_protocol.py --phase1 matched
  python scripts/12_phase2_protocol.py --phase1 learned --threshold 0.445
"""
import sys
import math
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import torch
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             accuracy_score, confusion_matrix)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR, SEED,
                             MC_SPLIT_STRATEGY, MC_HARD_CLASSES,
                             TRUSTLAB_MC_BASELINE, TRUSTLAB_KNOWN_CONFUSIONS,
                             TRUSTLAB_BASELINE, PHASE1_DETECTOR)
from src.common import get_logger, banner, clean_features, save_json, human
from src.metrics import per_class_f1_ci
from src.models import (build, device, build_xgboost_multiclass,
                        free_gpu)

log = get_logger("12_phase2")

MODES = ("oracle", "matched", "learned")

# A 95% CI wider than this cannot support a claim about a class. It is a
# reporting guard, not a modelling choice: 0.10 is roughly the size of the
# per-class differences this study is trying to detect, so an interval that
# wide is consistent with both "matches the baseline" and "misses it badly".
CI_WIDE = 0.10

# The interval alone is not enough, because the bootstrap resamples the errors
# it actually observed. A class the model got entirely right therefore reports
# a zero-width interval however few flows it saw. The run that prompted this
# guard had BufferOverflow at 1.0000 [1.000, 1.000] on eleven flows, which
# reads as certainty and is nothing of the kind: the plug-in principle
# breaking down on a degenerate sample, not evidence. Zero-width intervals
# still appear -- DNS reaches one on 1,284 flows -- but only where the support
# behind them makes a perfect score believable, which is the guard working.
#
# The rule of three supplies the guard and ties it to CI_WIDE rather than
# leaving it arbitrary: with zero errors observed in n trials, the 95% upper
# bound on the true error rate is about 3/n. So a class needs at least
# 3 / CI_WIDE flows before a zero-width interval can be honest; below that,
# a perfect score cannot be told apart from a CI_WIDE error rate.
MIN_SUPPORT = math.ceil(3 / CI_WIDE)      # 30 flows at CI_WIDE = 0.10

ap = argparse.ArgumentParser()
ap.add_argument("--phase1", nargs="+", default=["all"],
                choices=list(MODES) + ["all"],
                help="which Phase-1 filter(s) to put in front of Phase 2")
ap.add_argument("--strategy", choices=["random", "temporal"],
                default=MC_SPLIT_STRATEGY)
ap.add_argument("--arm", default="combined",
                help="script-05 arm supplying the learned detector")
ap.add_argument("--detector", default=PHASE1_DETECTOR,
                help=f"learned Phase-1 model name (default {PHASE1_DETECTOR} "
                     f"from config.settings.PHASE1_DETECTOR)")
# Each rung is a full sixteen-class fit, so a three-rung run is a long job.
# Rung-level resume: a rung whose JSON is already written is skipped.
ap.add_argument("--resume", action="store_true",
                help="skip rungs already written to results/phase2_<strategy>/")
ap.add_argument("--threshold", type=float, default=0.445,
                help="learned Phase-1 decision threshold (the paper used 0.445)")
args = ap.parse_args()
modes = list(MODES) if "all" in args.phase1 else [m for m in MODES
                                                 if m in args.phase1]

feats = joblib.load(ARTIFACTS_DIR / "mc_features.pkl")
classes = list(joblib.load(ARTIFACTS_DIR / "mc_classes.pkl"))
BENIGN = classes.index("Benign") if "Benign" in classes else -1
LAB = list(range(len(classes)))

AR = TRUSTLAB_BASELINE["attack_recall"]      # 0.9498
BR = TRUSTLAB_BASELINE["benign_recall"]      # 0.8229

# --------------------------------------------------------------------------
banner(log, "DATA")
splits = {}
for part in ("train", "test"):
    path = PROCESSED_DIR / f"mc_{part}_{args.strategy}.parquet"
    if not path.exists():
        log.error(f"Missing {path} -- run 08_build_multiclass.py first.")
        sys.exit(1)
    df = pd.read_parquet(path)
    splits[part] = (clean_features(df, feats).values,
                    np.array([classes.index(c) for c in df["folder_class"]]))
    log.info(f"  {part:<6} {human(len(splits[part][1])):>10} flows")
Xtr, ytr = splits["train"]
Xte, yte = splits["test"]

# --------------------------------------------------------------------------
det_path = None
if "learned" in modes:
    arm_dir = ARTIFACTS_DIR / args.arm
    if not (arm_dir / "scaler.pkl").exists():
        log.error(f"--phase1 learned needs a detector from script 05. Run:")
        log.error(f"    python scripts/05_train_binary.py --arm {args.arm}")
        sys.exit(1)
    # ".ckpt.pt" is an in-flight training checkpoint, not a model: the suffix
    # is ".pt" but the stem is "<name>.ckpt", which build() does not know.
    # Scripts 06 and 10 already exclude it for the same reason. Here it is
    # only reachable when --detector is empty, because a checkpoint's stem
    # never equals a model name -- but a candidate list that can contain a
    # thing the loader cannot load is worth closing rather than reasoning
    # about each time someone changes the filter above it.
    cands = [f for f in sorted(arm_dir.iterdir())
             if f.suffix in (".pkl", ".pt")
             and f.name not in ("scaler.pkl", "features.pkl")
             and not f.name.endswith(".ckpt.pt")]
    if args.detector:
        cands = [f for f in cands if f.stem == args.detector]
    if not cands:
        log.error(f"No usable detector in {arm_dir}.")
        sys.exit(1)
    det_path = cands[0]
    if args.detector and det_path.stem != args.detector:
        log.error(f"Detector {args.detector!r} not found in {arm_dir.name}. "
                  f"Available: {[f.stem for f in cands]}. Train it with "
                  f"05_train_binary.py, or set PHASE1_DETECTOR / pass "
                  f"--detector to choose one that exists.")
        sys.exit(1)

    if list(joblib.load(arm_dir / "features.pkl")) != list(feats):
        log.error("Detector feature list differs from the multiclass one.")
        sys.exit(1)
    scaler = joblib.load(arm_dir / "scaler.pkl")


def learned_mask(X):
    """Flows our script-05 detector calls attacks."""
    Xs = scaler.transform(X)
    if det_path.suffix == ".pt":
        m = build(det_path.stem, Xs.shape[1])
        m.load_state_dict(torch.load(det_path, map_location=device()))
        m.eval()
        out = []
        with torch.no_grad():
            for i in range(0, len(Xs), 8192):
                xb = torch.tensor(Xs[i:i + 8192].astype("float32")).to(device())
                out.append(torch.softmax(m(xb), 1).cpu().numpy())
        p = np.vstack(out)[:, 1]
    else:
        p = joblib.load(det_path).predict_proba(Xs)[:, 1]
    return p >= args.threshold


def phase1_mask(mode, X, y, seed_offset):
    """The Phase-1 filter for one rung of the ladder."""
    if mode == "oracle":
        return y != BENIGN
    if mode == "matched":
        # Their published operating point, applied class-independently.
        u = np.random.default_rng(SEED + seed_offset).random(len(y))
        return np.where(y == BENIGN, u < (1.0 - BR), u < AR)
    return learned_mask(X)


def run(mode):
    mtr = phase1_mask(mode, Xtr, ytr, 0)
    mte = phase1_mask(mode, Xte, yte, 1)
    banner(log, f"PHASE 1 = {mode.upper()}")
    if mode == "oracle":
        log.info("Perfect detector: every attack passes, no benign does. "
                 "CONTROL ONLY -- built from ground-truth labels.")
    elif mode == "matched":
        log.info(f"Their operating point: {AR*100:.2f}% of attacks pass, "
                 f"{(1-BR)*100:.2f}% of benign pass as false positives. "
                 f"CONTROL ONLY -- built from ground-truth labels.")
    else:
        log.info(f"Our detector {det_path.stem} (arm {args.arm}) at "
                 f"threshold {args.threshold}. This is the only rung that "
                 f"describes a system that could actually run.")
    log.info(f"  train {human(int(mtr.sum())):>9} / {human(len(ytr))} "
             f"({mtr.mean()*100:.1f}%)   "
             f"test {human(int(mte.sum())):>9} / {human(len(yte))} "
             f"({mte.mean()*100:.1f}%)")

    if mtr.sum() < 1000 or mte.sum() < 500:
        log.error("  Too few flows survive Phase 1 to train or score. "
                  "That is itself the finding for this rung.")
        return None

    Xtr_f, ytr_f = Xtr[mtr], ytr[mtr]
    Xte_f, yte_f = Xte[mte], yte[mte]

    # Classes Phase 1 removed entirely cannot be trained on. Remap survivors
    # to a contiguous range for XGBoost, then map predictions back so the
    # confusion matrix stays in the full sixteen-class space.
    present = np.unique(ytr_f)
    remap = {g: i for i, g in enumerate(present)}
    # The learned rung runs a PyTorch detector before this point, and torch
    # does not hand its cached GPU memory back on its own. Release it or
    # XGBoost fits an order of magnitude slower -- see free_gpu in
    # src/models.py.
    free_gpu()
    m = build_xgboost_multiclass(len(present))
    m.fit(Xtr_f, np.array([remap[v] for v in ytr_f]))
    pred = present[m.predict_proba(Xte_f).argmax(1)]

    p = precision_score(yte_f, pred, average=None, labels=LAB, zero_division=0)
    r = recall_score(yte_f, pred, average=None, labels=LAB, zero_division=0)
    f1 = f1_score(yte_f, pred, average=None, labels=LAB, zero_division=0)
    acc = accuracy_score(yte_f, pred)
    # A class with no test flows scores F1 0 on zero support. That is
    # arithmetic, not performance, and averaging it in would measure Phase 1.
    supported = [i for i in LAB if int((yte_f == i).sum()) > 0]
    macro = f1_score(yte_f, pred, average="macro", labels=supported,
                     zero_division=0)
    absent = [classes[i] for i in LAB if i not in supported]

    ci = per_class_f1_ci(yte_f, pred, len(classes), macro_over=supported,
                         seed=SEED)
    mlo = ci["macro"]["ci_low"] if ci["macro"] else float("nan")
    mhi = ci["macro"]["ci_high"] if ci["macro"] else float("nan")
    log.info(f"  accuracy {acc:.4f}   macro F1 {macro:.4f} "
             f"[{mlo:.4f}, {mhi:.4f}]   "
             f"(over the {len(supported)} classes that reached Phase 2)")
    if absent:
        log.warning(f"  Phase 1 passed no test flows of: {absent} -- shown "
                    f"as n/a, excluded from the macro average.")
    log.info("  Accuracy and macro F1 are computed on the flows Phase 1 let "
             "through, so their denominator moves between rungs and "
             "thresholds and they cannot be compared across them. 'e2e "
             "recall' below can: its denominator is every test flow of the "
             "class, passed or not.")

    log.info(f"\n  {'class':<16}{'F1':>8}{'95% CI':>17}{'ref':>6}{'diff':>8}"
             f"{'support':>9}{'passed':>8}{'e2e rec':>9}")
    per_class = {}
    for i, c in enumerate(classes):
        ref = TRUSTLAB_MC_BASELINE.get(c, {}).get("f1")
        sup = int((yte_f == i).sum())
        total = int((yte == i).sum())            # fixed denominator
        rate = float((mte & (yte == i)).sum() / max(1, total))
        # End-to-end recall: of every test flow of this class, the share the
        # whole pipeline both passed AND labelled correctly.
        e2e = float(((yte_f == i) & (pred == i)).sum() / max(1, total))
        cinf = ci["per_class"].get(i, {})
        lo, hi = cinf.get("ci_low"), cinf.get("ci_high")
        width = cinf.get("ci_width")
        mark = "  <- hard" if c in MC_HARD_CLASSES else ""
        if sup and sup < MIN_SUPPORT:
            mark += f"   <- only {sup} flows, below the {MIN_SUPPORT}-flow floor"
        elif width is not None and width > CI_WIDE:
            mark += f"   <- CI spans {width:.2f}, too wide to quote"

        if sup == 0:
            log.info(f"  {c:<16}{'n/a':>8}{'n/a':>17}"
                     f"{(ref if ref else float('nan')):>6.2f}{'n/a':>8}"
                     f"{0:>9,}{rate*100:>7.1f}%{e2e:>9.4f}{mark}")
            per_class[c] = {"f1": None, "support": 0, "reference_f1": ref,
                            "diff": None, "phase1_passthrough": rate,
                            "end_to_end_recall": e2e, "ci_low": None,
                            "ci_high": None, "ci_width": None,
                            "quotable": False}
            continue

        d = (f1[i] - ref) if ref is not None else None
        log.info(f"  {c:<16}{f1[i]:>8.4f}  [{lo:.3f}, {hi:.3f}]"
                 f"{(ref if ref else float('nan')):>6.2f}"
                 f"{(d if d is not None else float('nan')):>+8.4f}"
                 f"{sup:>9,}{rate*100:>7.1f}%{e2e:>9.4f}{mark}")
        per_class[c] = {"precision": float(p[i]), "recall": float(r[i]),
                        "f1": float(f1[i]), "support": sup,
                        "reference_f1": ref,
                        "diff": (float(d) if d is not None else None),
                        "phase1_passthrough": rate,
                        "end_to_end_recall": e2e,
                        "ci_low": lo, "ci_high": hi, "ci_width": width,
                        "quotable": bool(sup >= MIN_SUPPORT
                                         and width is not None
                                         and width <= CI_WIDE)}

    # Two different reasons a class cannot be quoted, and they mean different
    # things: no support at all is structural (this filter admits none of it),
    # a wide interval is statistical (too few flows to pin the number down).
    none_passed = [c for c, v in per_class.items() if v["support"] == 0]
    thin = [c for c, v in per_class.items()
            if v["support"] > 0 and not v["quotable"]]
    if none_passed:
        log.warning(f"  No test flows reached Phase 2: {none_passed}. Nothing "
                    f"is measurable for them at this rung -- that is a "
                    f"property of the filter, not a score of zero.")
    if thin:
        log.warning(f"  Measured but not quotable -- fewer than "
                    f"{MIN_SUPPORT} flows, or a 95% CI wider than "
                    f"{CI_WIDE:.2f}: {thin}. Their F1 rests on too few flows "
                    f"to separate a real effect from sampling noise; one flow "
                    f"changing moves it. Cite the e2e recall column for these "
                    f"instead, which has a fixed denominator.")

    cm = confusion_matrix(yte_f, pred, labels=LAB)
    log.info(f"\n  documented confusions (share of the true class -- raw "
             f"counts are not comparable, their test set is larger):")
    log.info(f"  {'confusion':<34}{'theirs':>9}{'ours':>9}{'ratio':>9}")
    confusions = []
    for a, b, n_pub, why in TRUSTLAB_KNOWN_CONFUSIONS:
        if a not in classes or b not in classes:
            continue
        i, j = classes.index(a), classes.index(b)
        n_here, sup_here = int(cm[i, j]), int(cm[i].sum())
        r_here = n_here / max(1, sup_here)
        sup_pub = TRUSTLAB_MC_BASELINE.get(a, {}).get("support")
        r_pub = (n_pub / sup_pub) if sup_pub else None
        ratio = (r_here / r_pub) if r_pub else None
        log.info(f"  {a + ' -> ' + b:<34}"
                 f"{(r_pub * 100 if r_pub else float('nan')):>8.2f}%"
                 f"{r_here * 100:>8.2f}%"
                 f"{(ratio if ratio is not None else float('nan')):>8.2f}x")
        confusions.append({"from": a, "to": b, "their_explanation": why,
                           "published_rate": r_pub, "our_rate": float(r_here),
                           "our_n": n_here, "our_support": sup_here,
                           "rate_ratio": (float(ratio) if ratio is not None
                                          else None)})

    out_dir = RESULTS_DIR / f"phase2_{args.strategy}"
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(cm, index=[f"true_{c}" for c in classes],
                 columns=[f"pred_{c}" for c in classes]).to_csv(
        out_dir / f"phase1_{mode}_confusion.csv")

    payload = {"phase1": mode, "strategy": args.strategy,
               "is_control": mode in ("oracle", "matched"),
               "accuracy": float(acc), "macro_f1": float(macro),
               "macro_f1_ci": ci["macro"],
               "ci_method": ("nonparametric bootstrap over the test set, "
                             f"{ci['n_boot']} resamples, 95% percentile "
                             "interval"),
               "quotable_rule": (
                   f"support >= {MIN_SUPPORT} (rule of three at "
                   f"CI_WIDE={CI_WIDE}) AND 95% CI width <= {CI_WIDE}"),
               "macro_over_classes": [classes[i] for i in supported],
               "classes_absent_from_phase2": absent,
               "n_train_flagged": int(mtr.sum()),
               "n_test_flagged": int(mte.sum()),
               "per_class": per_class, "documented_confusions": confusions,
               "confusion_matrix": {"labels": classes, "matrix": cm.tolist()}}
    if mode == "learned":
        payload.update({"arm": args.arm, "detector": det_path.stem,
                        "threshold": args.threshold})
    if mode == "matched":
        payload.update({"matched_attack_recall": AR,
                        "matched_benign_fpr": 1.0 - BR})
    payload["protocol_note"] = (
        "Phase-2 protocol replication. 'oracle' and 'matched' are "
        "counterfactual controls built from ground-truth labels and are NOT "
        "achievable performance; only 'learned' describes a runnable system. "
        "Compare 'matched' against the published per-class F1 -- it is the "
        "rung that shares their Phase-1 operating point.")
    save_json(payload, f"phase2_{args.strategy}", f"phase1_{mode}.json")
    return payload


results = {}
for mode in modes:
    prev = RESULTS_DIR / f"phase2_{args.strategy}" / f"phase1_{mode}.json"
    if args.resume and prev.exists():
        import json as _json
        results[mode] = _json.load(open(prev, encoding="utf-8"))
        log.info(f"{mode}: already computed ({prev.name}), skipped")
        continue
    out = run(mode)
    if out:
        results[mode] = out

# --------------------------------------------------------------------------
if len(results) > 1:
    banner(log, "DECOMPOSING THE GAP")
    log.info("Every rung uses the same Phase-2 model and the same splits, so "
             "differences between them are caused only by which flows Phase 1 "
             "let through.")
    log.info(f"\n  {'':<18}{'oracle':>9}{'matched':>9}{'learned':>9}"
             f"{'ref':>7}   {'detector cost':>14}{'our deficit':>13}"
             f"{'vs published':>14}")

    def g(mode, c):
        v = results.get(mode, {}).get("per_class", {}).get(c, {}).get("f1")
        return v

    for c in classes:
        o, m_, l = g("oracle", c), g("matched", c), g("learned", c)
        ref = TRUSTLAB_MC_BASELINE.get(c, {}).get("f1")
        cells = "".join(f"{(v if v is not None else float('nan')):>9.4f}"
                        for v in (o, m_, l))
        det_cost = (o - m_) if (o is not None and m_ is not None) else None
        deficit = (m_ - l) if (m_ is not None and l is not None) else None
        vs_pub = (m_ - ref) if (m_ is not None and ref is not None) else None
        mark = "  <- hard" if c in MC_HARD_CLASSES else ""
        log.info(f"  {c:<18}{cells}{(ref if ref else float('nan')):>7.2f}   "
                 f"{(det_cost if det_cost is not None else float('nan')):>+14.4f}"
                 f"{(deficit if deficit is not None else float('nan')):>+13.4f}"
                 f"{(vs_pub if vs_pub is not None else float('nan')):>+14.4f}"
                 f"{mark}")

    log.info("\n  detector cost = oracle - matched   what realistic Phase-1 "
             "error costs Phase 2, at THEIR operating point")
    log.info("  our deficit   = matched - learned   what OUR detector being "
             "weaker than theirs costs on top of that")
    log.info("  vs published  = matched - reference the genuine "
             "classifier/data difference, with Phase-1 quality held equal --")
    log.info("                                      this is the column the "
             "comparison was always trying to isolate")
    log.info("")
    log.warning("oracle and matched are controls built from true labels. "
                "Report 'learned' as this pipeline's result; report "
                "'matched' only as the like-for-like comparison against the "
                "paper, labelled as a control.")

banner(log, "DONE")
log.info(f"Written to {RESULTS_DIR / ('phase2_' + args.strategy)}")
