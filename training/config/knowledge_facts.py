"""
knowledge_facts.py
------------------
Recompute every number the retrieval corpus states, and put it back.

WHY THIS EXISTS
knowledge/ is what the deployed tool hands an investigator as measured model
reliability. Those figures were written into the prose by hand and nothing
recomputed them, so successive reruns left the corpus quoting a model that no
longer existed -- a test F1 from a superseded run, presented as measured fact
and acted on. That is worse than quoting no figure at all.

The files stay hand-written. Only the numbers inside them are generated: each
claim below names a file, a regex whose single group is the number, and the
fact that should be there. Reword the sentence around a number freely; the
pattern only has to keep matching, and an unmatched pattern is reported as a
failure rather than passed over -- a number that has stopped being checked is
exactly how the corpus drifted in the first place.

Usage:
  python config/knowledge_facts.py           # check, exit 1 on drift
  python config/knowledge_facts.py --write   # rewrite the numbers in place
"""
import re
import sys
import json
import argparse
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
KNOWLEDGE = ROOT / "knowledge"

WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
         7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven",
         12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen",
         16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen",
         20: "twenty", 21: "twenty-one", 22: "twenty-two",
         23: "twenty-three", 24: "twenty-four", 25: "twenty-five",
         26: "twenty-six", 27: "twenty-seven", 28: "twenty-eight",
         29: "twenty-nine", 30: "thirty"}


def word(n, cap=False):
    """Spell a small integer, because the prose spells them."""
    w = WORDS.get(int(n), str(int(n)))
    return w[0].upper() + w[1:] if cap else w


def facts():
    """Every number the corpus states, recomputed from results/."""
    mc = json.loads((RESULTS / "mc_random" / "XGBoost_test.json")
                    .read_text(encoding="utf-8"))
    pc = mc["per_class"]
    ext = pd.read_csv(RESULTS / "external_validation.csv")
    shap = json.loads((RESULTS / "shap" / "pair_slowloris_dos_random.json")
                      .read_text(encoding="utf-8"))
    shift = json.loads((RESULTS / "external_shift_66.json")
                       .read_text(encoding="utf-8"))

    conf = pd.read_csv(RESULTS / "mc_random" / "XGBoost_confusion.csv",
                       index_col=0)
    conf.index = [x.replace("true_", "") for x in conf.index]
    conf.columns = [x.replace("pred_", "") for x in conf.columns]

    tr = pd.read_parquet(ROOT / "data" / "processed" / "mc_train_random.parquet",
                         columns=["folder_class"])
    te = pd.read_parquet(ROOT / "data" / "processed" / "mc_test_random.parquet",
                         columns=["folder_class"])
    # Take the training size from what script 09 recorded rather than
    # recomputing it. The validation split groups rows by feature vector and
    # cannot land on MC_VAL_FRACTION exactly, so any fraction applied here
    # would disagree with the split the models were actually trained on -- by
    # two rows, which is enough for this tool to "correct" a correct number.
    n_train = json.loads((RESULTS / "mc_random" / "XGBoost_internal.json")
                         .read_text(encoding="utf-8"))["n_train"]
    n_val = len(tr) - n_train

    internal = []
    for arm in ("combined", "cicids_only", "tii_only"):
        for m in ("XGBoost", "MLP", "CNN1D", "CNN_BiLSTM", "LSTM"):
            d = json.loads((RESULTS / arm / f"{m}_internal.json")
                           .read_text(encoding="utf-8"))
            internal.append(d["internal_validation"]["accuracy"])

    expl = conf.loc["Exploitation"]
    return {
        "mc_accuracy": f"{mc['accuracy']:.4f}",
        "mc_macro_f1": f"{mc['macro_f1']:.4f}",
        "f1_dos": f"{pc['DoS']['f1']:.4f}",
        "f1_slowloris": f"{pc['Slowloris']['f1']:.4f}",
        "f1_exploitation": f"{pc['Exploitation']['f1']:.4f}",
        "f1_bufferoverflow": f"{pc['BufferOverflow']['f1']:.4f}",
        "n_strong_word": word(sum(1 for v in pc.values() if v["f1"] >= 0.94),
                              cap=True),
        "ext_mean_auc": f"{ext.roc_auc.mean():.4f}",
        "ext_below_half_word": word(int((ext.roc_auc < 0.50).sum())),
        "n_train": f"{n_train:,}",
        "n_val": f"{n_val:,}",
        "n_test": f"{len(te):,}",
        "n_features": str(shift["n_features"]),
        "shift_combined_word": word(shift["arms"]["combined"]["over_3sd"],
                                    cap=True),
        "shift_cicids_word": word(shift["arms"]["cicids_only"]["over_3sd"]),
        # Three decimals, not two: the best arm scores 0.9989, which renders
        # as "1.00" at two and would claim a perfect detector.
        "internal_low": f"{min(internal):.3f}",
        "internal_high": f"{max(internal):.3f}",
        "shap_corr": f"{shap['importance_correlation']:.4f}",
        "shap_shared_word": word(len(shap["shared_top10"])),
        "expl_bo_pct": f"{expl['BufferOverflow'] / expl.sum() * 100:.1f}",
    }


# (file under knowledge/, regex with exactly one capturing group, fact key)
CLAIMS = [
    ("datasets/scope.md", r"Test accuracy (\d\.\d{4})", "mc_accuracy"),
    ("datasets/scope.md", r"macro F1 (\d\.\d{4})\.", "mc_macro_f1"),
    ("datasets/scope.md", r"\| DoS \| (\d\.\d{4}) \|", "f1_dos"),
    ("datasets/scope.md", r"\| Slowloris \| (\d\.\d{4}) \|", "f1_slowloris"),
    ("datasets/scope.md", r"\| Exploitation \| (\d\.\d{4}) \|", "f1_exploitation"),
    ("datasets/scope.md", r"\| BufferOverflow \| (\d\.\d{4}) \|", "f1_bufferoverflow"),
    ("datasets/scope.md", r"(\w+) of sixteen classes are at F1 0\.94", "n_strong_word"),
    ("datasets/scope.md", r"mean ROC-AUC (\d\.\d{4})", "ext_mean_auc"),
    ("datasets/scope.md", r"with (\w+) of fifteen below 0\.50", "ext_below_half_word"),
    ("datasets/scope.md", r"TRUSTLab\. ([\d,]+) training flows", "n_train"),
    ("datasets/scope.md", r"([\d,]+)\nheld out for early stopping", "n_val"),
    ("datasets/scope.md", r"and ([\d,]+) held-out test flows", "n_test"),
    ("datasets/scope.md", r"(\w+) of the \d+ features differ", "shift_combined_word"),
    ("datasets/scope.md", r"of the (\d+) features differ", "n_features"),
    ("datasets/scope.md", r"and ([\w-]+) do\nfor the CICIDS2018-only", "shift_cicids_word"),
    ("datasets/scope.md", r"despite scoring (\d\.\d{3})-\d\.\d{3} on their own", "internal_low"),
    ("datasets/scope.md", r"despite scoring \d\.\d{3}-(\d\.\d{3}) on their own", "internal_high"),
    ("detection/attack_dos.md", r"correlates at (\d\.\d{4})", "shap_corr"),
    ("detection/attack_dos.md", r"and (\w+) of the top ten", "shap_shared_word"),
    ("detection/attack_slowloris.md", r"correlates at (\d\.\d{4})", "shap_corr"),
    ("detection/attack_slowloris.md", r"and (\w+) of the top ten", "shap_shared_word"),
    ("interpretability/caveats.md", r"importance correlation of \*\*(\d\.\d{4})\*\*", "shap_corr"),
    ("detection/attack_bufferoverflow.md", r"confuses these in (\d+\.\d)% of cases", "expl_bo_pct"),
    ("detection/attack_exploitation.md", r"confused in (\d+\.\d)% of cases", "expl_bo_pct"),
]


def main():
    ap = argparse.ArgumentParser(
        description="Check or rewrite the measured figures in knowledge/.")
    ap.add_argument("--write", action="store_true",
                    help="rewrite the numbers in place (default: check only)")
    args = ap.parse_args()

    f = facts()
    drift, unmatched, edited = [], [], {}
    for rel, pattern, key in CLAIMS:
        path = KNOWLEDGE / rel
        text = edited.get(rel, path.read_text(encoding="utf-8"))
        m = re.search(pattern, text)
        if m is None:
            unmatched.append(f"{rel}: {pattern!r} no longer matches, so "
                             f"{key} is not being checked")
            continue
        want = f[key]
        if m.group(1) != want:
            drift.append(f"{rel}: {key} reads {m.group(1)!r}, "
                         f"results say {want!r}")
            if args.write:
                s, e = m.span(1)
                edited[rel] = text[:s] + want + text[e:]

    if args.write:
        for rel, text in edited.items():
            (KNOWLEDGE / rel).write_text(text, encoding="utf-8")

    for line in unmatched:
        print(f"  UNMATCHED  {line}")
    for line in drift:
        print(("  REWROTE    " if args.write else "  DRIFT      ") + line)
    if not drift and not unmatched:
        print(f"  knowledge/ agrees with results/ on all {len(CLAIMS)} figures.")
    return 1 if unmatched or (drift and not args.write) else 0


if __name__ == "__main__":
    sys.exit(main())
