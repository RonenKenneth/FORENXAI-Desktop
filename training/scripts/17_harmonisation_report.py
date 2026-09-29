"""
17_harmonisation_report.py
--------------------------
Before / after table for the scoring-time feature harmonisation.

Reads the main external results (scripts 06 and 13, no flags) and the
harmonised runs (--harmonise, and --harmonise --timeout-subset) and writes
results/tables/10_harmonisation_before_after.csv.

Metric for both experiments: macro recall.
  binary    (attack recall + benign recall) / 2, i.e. balanced accuracy;
            0.50 is chance. ROC-AUC is reported beside it.
  16-class  mean recall over the TRUSTLab classes the external sets share
            (exact class); chance is about 1/16. The TRUSTLab reference on
            the same classes is reported beside it.

Usage:
  python scripts/17_harmonisation_report.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import RESULTS_DIR
from src.common import get_logger, banner

log = get_logger("17_harmonise_report")

VARIANTS = {"original": (), "harmonised": ("harmonised", "fixes"),
            "harmonised + 120 s subset": ("harmonised", "fixes_120s")}


def binary_rows():
    rows = []
    for label, parts in VARIANTS.items():
        folder = RESULTS_DIR.joinpath(*parts, "external")
        for f in sorted(folder.glob("*__*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            e = d["external_validation"]
            rows.append({"experiment": "binary -> TRUSTLab", "variant": label,
                         "arm": d["arm"], "model": d["model"],
                         "macro_recall": (e["attack_recall"] + e["benign_recall"]) / 2,
                         "roc_auc": e.get("roc_auc"),
                         "rows": d.get("harmonised", {}).get("rows")})
    return rows


def multiclass_rows():
    rows = []
    for label, parts in VARIANTS.items():
        f = RESULTS_DIR.joinpath(*parts, "reverse_transfer_mc", "reverse_transfer_mc.json")
        if not f.exists():
            continue
        for m in json.loads(f.read_text(encoding="utf-8"))["models"]:
            rows.append({"experiment": "16-class TRUSTLab -> others", "variant": label,
                         "arm": "trustlab", "model": m["model"],
                         "macro_recall": m["mean_ext_exact"],
                         "family_recall": m["mean_ext_family"],
                         "cse_exact": m.get("cse_exact"), "tii_exact": m.get("tii_exact"),
                         "trustlab_reference": m["ref_macro_recall_mapped"]})
    return rows


df = pd.DataFrame(binary_rows() + multiclass_rows())
if df.empty:
    log.error("No results found. Run scripts 06 and 13 with and without --harmonise first.")
    sys.exit(1)
out = RESULTS_DIR / "tables" / "10_harmonisation_before_after.csv"
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)

banner(log, "MEAN OVER MODELS")
summary = (df.groupby(["experiment", "variant"], sort=False)
             [["macro_recall", "roc_auc", "family_recall", "trustlab_reference"]]
             .mean().round(4))
log.info("\n" + summary.to_string())
banner(log, "XGBOOST")
xgb = df[df["model"] == "XGBoost"].set_index(["experiment", "arm", "variant"])
log.info("\n" + xgb[["macro_recall", "roc_auc", "family_recall", "trustlab_reference"]]
         .round(4).to_string())
log.info(f"\nwrote {out}")
