"""
07_aggregate_results.py
-----------------------
Collects every result JSON into comparison tables ready for the results
chapter.

TABLES PRODUCED (results/tables/)
  01_main_comparison.csv        every model x arm, internal and external
  02_generalisation_gap.csv     internal minus external -- the transfer cost
  03_vs_published.csv           each model against the TRUSTLab baseline
  04_arm_comparison.csv         what each training source contributes
  05_architecture.csv           deep architectures vs the tree control
  06_per_class.csv              accuracy by TRUSTLab attack family

THE TABLE THAT MATTERS MOST
02_generalisation_gap. A model scoring 0.98 internally and 0.35 externally
has not learned to detect attacks -- it has learned the training environment.
The gap quantifies that directly, and it is the number most published work
never reports because it never tests outside its training distribution.

Run this at any point; it works on whatever results exist so far.

Usage:  python scripts/07_aggregate_results.py
"""
import sys
import json
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (RESULTS_DIR, TRUSTLAB_BASELINE, DL_MODELS,
                             TRAINING_ARMS)
from src.common import get_logger, banner

log = get_logger("07_aggregate")
pd.set_option("display.width", 220)
pd.set_option("display.max_columns", 40)

out = RESULTS_DIR / "tables"
out.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
internal = []
# Iterate the binary arms by name rather than globbing */. Script 09 writes
# results/mc_<strategy>/<model>_internal.json too, and those files describe a
# sixteen-class run with no "internal_validation" key at all -- a glob picks
# them up and this aggregation dies on the first one. The two experiments
# share a results/ tree, so anything reading it has to say which one it wants.
for arm in TRAINING_ARMS:
    for f in sorted((RESULTS_DIR / arm).glob("*_internal.json")):
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
        m = d["internal_validation"]
        internal.append({"arm": d["arm"], "model": d["model"],
                         "int_acc": m["accuracy"], "int_f1": m["f1"],
                         "int_f2": m["f2"],
                         "int_benign_recall": m["benign_recall"],
                         "int_attack_recall": m["attack_recall"],
                         "train_seconds": d.get("train_seconds")})

external, per_class = [], []
# Filter by arm rather than taking whatever the glob returns, for the same
# reason the internal loop above does. An older, buggy script 06 wrote
# external/mc_random__XGBoost.json -- a sixteen-class model scored as though
# it were a binary detector, ROC-AUC 0.0005. Deleting that file fixes today;
# checking the arm stops any stale or foreign result reaching these tables
# again.
for f in sorted((RESULTS_DIR / "external").glob("*.json")
                if (RESULTS_DIR / "external").exists() else []):
    with open(f, encoding="utf-8") as fh:
        d = json.load(fh)
    if d.get("arm") not in TRAINING_ARMS:
        log.warning(f"Skipping {f.name}: arm {d.get('arm')!r} is not a binary "
                    f"training arm. Delete it if it is left over.")
        continue
    m = d["external_validation"]
    external.append({"arm": d["arm"], "model": d["model"],
                     "ext_acc": m["accuracy"], "ext_f1": m["f1"],
                     "ext_f2": m["f2"], "ext_roc_auc": m.get("roc_auc"),
                     "ext_benign_recall": m["benign_recall"],
                     "ext_attack_recall": m["attack_recall"],
                     "ext_false_alarm": m["false_alarm_rate"]})
    for cls, v in (d.get("per_class_accuracy") or {}).items():
        per_class.append({"arm": d["arm"], "model": d["model"],
                          "class": cls, "n": v["n"],
                          "accuracy": v["accuracy"]})

if not internal and not external:
    log.error("No results found. Run scripts 05 and 06 first.")
    sys.exit(1)

di = pd.DataFrame(internal)
de = pd.DataFrame(external)
main = (di.merge(de, on=["arm", "model"], how="outer")
        if not di.empty and not de.empty
        else (di if de.empty else de))

banner(log, "MAIN COMPARISON")
log.info("\n" + main.to_string(index=False))
main.to_csv(out / "01_main_comparison.csv", index=False)

# --------------------------------------------------------------------------
if not di.empty and not de.empty:
    banner(log, "GENERALISATION GAP")
    log.info("Internal accuracy is on held-out data from the SAME capture "
             "environments used for training. External is TRUSTLab, unseen. "
             "The gap is the cost of transfer.")
    g = main.copy()
    g["gap_acc"] = g["int_acc"] - g["ext_acc"]
    g["gap_benign_recall"] = g["int_benign_recall"] - g["ext_benign_recall"]
    g = g[["arm", "model", "int_acc", "ext_acc", "gap_acc",
           "int_benign_recall", "ext_benign_recall", "gap_benign_recall"]]
    g = g.sort_values("gap_acc")
    log.info("\n" + g.round(4).to_string(index=False))
    g.to_csv(out / "02_generalisation_gap.csv", index=False)

    worst = g.iloc[-1]
    best = g.iloc[0]
    log.info(f"\nSmallest gap: {best['model']} ({best['arm']}) "
             f"{best['gap_acc']:+.4f}")
    log.info(f"Largest gap:  {worst['model']} ({worst['arm']}) "
             f"{worst['gap_acc']:+.4f}")
    if worst["gap_acc"] > 0.3:
        log.warning("A gap above 0.30 means the model learned the training "
                    "environment more than it learned attack behaviour. This "
                    "belongs in the findings, stated plainly.")

# --------------------------------------------------------------------------
if not de.empty:
    banner(log, "AGAINST THE PUBLISHED BASELINE")
    log.info(TRUSTLAB_BASELINE["source"])
    v = de.copy()
    v["baseline_acc"] = TRUSTLAB_BASELINE["accuracy"]
    v["delta_acc"] = v["ext_acc"] - TRUSTLAB_BASELINE["accuracy"]
    v["baseline_f2"] = TRUSTLAB_BASELINE["f2"]
    v["delta_f2"] = v["ext_f2"] - TRUSTLAB_BASELINE["f2"]
    v = v[["arm", "model", "ext_acc", "baseline_acc", "delta_acc",
           "ext_f2", "baseline_f2", "delta_f2"]].sort_values(
               "delta_acc", ascending=False)
    log.info("\n" + v.round(4).to_string(index=False))
    v.to_csv(out / "03_vs_published.csv", index=False)

    beat = int((v["delta_acc"] > 0).sum())
    log.info(f"\n{beat} of {len(v)} configurations exceed the published "
             f"accuracy.")
    log.info("Both are cross-dataset transfer into TRUSTLab, so the protocol "
             "is comparable -- but the source datasets differ, so a gap "
             "reflects source data as much as architecture.")

# --------------------------------------------------------------------------
if not de.empty and de["arm"].nunique() > 1:
    banner(log, "TRAINING ARM COMPARISON")
    log.info("combined = CICIDS2018 + TII-SSRC-23; the others are controls.")
    a = (de.groupby("arm")
         .agg(models=("model", "count"),
              mean_ext_acc=("ext_acc", "mean"),
              best_ext_acc=("ext_acc", "max"),
              mean_benign_recall=("ext_benign_recall", "mean"))
         .reset_index().sort_values("best_ext_acc", ascending=False))
    log.info("\n" + a.round(4).to_string(index=False))
    a.to_csv(out / "04_arm_comparison.csv", index=False)

    arms = set(a["arm"])
    if {"combined", "cicids_only"} <= arms:
        c = a.loc[a["arm"] == "combined", "best_ext_acc"].iloc[0]
        o = a.loc[a["arm"] == "cicids_only", "best_ext_acc"].iloc[0]
        log.info(f"\ncombined vs cicids_only: {c - o:+.4f}")
        log.info("  If close to zero, TII-SSRC-23 contributed little beyond "
                 "what CICIDS2018 already provided.")
    if "tii_only" in arms:
        t = a.loc[a["arm"] == "tii_only", "best_ext_acc"].iloc[0]
        log.info(f"tii_only best external accuracy: {t:.4f}")
        log.info("  Expected to be poor -- ~1,301 benign training flows. This "
                 "is the evidence that combining was necessary.")

# --------------------------------------------------------------------------
if not de.empty:
    banner(log, "ARCHITECTURE: DEEP vs TREE")
    d = de.copy()
    d["family"] = d["model"].apply(
        lambda m: "deep" if m in DL_MODELS else "tree")
    f = (d.groupby("family")
         .agg(n=("model", "count"),
              mean_ext_acc=("ext_acc", "mean"),
              best_ext_acc=("ext_acc", "max"),
              mean_benign_recall=("ext_benign_recall", "mean"))
         .reset_index())
    log.info("\n" + f.round(4).to_string(index=False))
    f.to_csv(out / "05_architecture.csv", index=False)

    if {"deep", "tree"} <= set(f["family"]):
        bd = f.loc[f["family"] == "deep", "best_ext_acc"].iloc[0]
        bt = f.loc[f["family"] == "tree", "best_ext_acc"].iloc[0]
        log.info(f"\nBest deep {bd:.4f} vs best tree {bt:.4f} "
                 f"({bd - bt:+.4f})")
        if bt >= bd:
            log.info("The tree control matched or beat every deep "
                     "architecture. Report it -- it is a legitimate finding, "
                     "not a gap in the comparison.")

# --------------------------------------------------------------------------
if per_class:
    banner(log, "PER-CLASS ACCURACY ON TRUSTLAB")
    pc = pd.DataFrame(per_class)
    piv = pc.pivot_table(index="class", columns="model",
                         values="accuracy", aggfunc="mean")
    piv["mean"] = piv.mean(axis=1)
    piv = piv.sort_values("mean", ascending=False)
    log.info("\n" + piv.round(4).to_string())
    pc.to_csv(out / "06_per_class.csv", index=False)
    log.info("\nUniform failure across classes points to a distribution "
             "problem; selective failure points to specific attack families "
             "being harder to transfer. They mean different things.")

# --------------------------------------------------------------------------
# The retrieval corpus quotes measured figures -- test F1s, the external
# ROC-AUC, the split sizes -- and nothing recomputes them, so it has gone
# stale three times, each rerun leaving the deployed tool describing a model
# that no longer existed. Results have just changed, which is the moment to
# notice.
#
# Warning only, on purpose. This script's job is to turn results into tables,
# and someone reproducing the numbers with no interest in the forensic tool
# should not be blocked by documents they never intend to use. It never
# changes the exit code, and a missing knowledge/ or an import failure is
# passed over in silence rather than turned into a failure of aggregation.
try:
    from config.knowledge_facts import facts, CLAIMS, KNOWLEDGE
    import re as _re

    if KNOWLEDGE.exists():
        _f = facts()
        _stale = []
        for _rel, _pat, _key in CLAIMS:
            _m = _re.search(_pat, (KNOWLEDGE / _rel).read_text(encoding="utf-8"))
            if _m is None:
                _stale.append(f"{_rel}: {_key} is no longer being checked")
            elif _m.group(1) != _f[_key]:
                _stale.append(f"{_rel}: {_key} reads {_m.group(1)}, "
                              f"results say {_f[_key]}")
        if _stale:
            banner(log, "RETRIEVAL CORPUS IS OUT OF DATE")
            for _line in _stale:
                log.warning(f"  {_line}")
            log.warning("\n  knowledge/ is what the deployed tool hands an "
                        "investigator as measured reliability. Refresh it:")
            log.warning("    python config/knowledge_facts.py --write")
except Exception as _e:                                  # never fail on this
    log.debug(f"corpus check skipped: {type(_e).__name__}: {_e}")

banner(log, "DONE")
log.info(f"Tables written to {out}")
