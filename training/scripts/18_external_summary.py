"""
18_external_summary.py
----------------------
One table for both external validations, on a common metric.

  results/tables/11_external_validation_summary.csv

Rows: every binary detector (3 training arms x 5 models, tested on TRUSTLab)
and every sixteen-class model (trained on TRUSTLab, tested on
CSE-CIC-IDS2018 and TII-SSRC-23). Macro recall is the shared metric:
  binary    (attack recall + benign recall) / 2; chance 0.50
  16-class  mean recall over the TRUSTLab classes with a counterpart in the
            external set (exact class); chance 1/16 = 0.0625
"own_data" is the same model on held-out data from its own training source
(for the 16-class models: TRUSTLab, over exactly the classes scored
externally). Reads the main results only (scripts 05, 06, 13; no flags).

Usage:
  python scripts/18_external_summary.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import RESULTS_DIR

ARM_NAME = {"cicids_only": "CSE-CIC-IDS2018", "tii_only": "TII-SSRC-23",
            "combined": "CSE-CIC-IDS2018 + TII-SSRC-23"}
rows = []

for f in sorted((RESULTS_DIR / "external").glob("*__*.json")):
    d = json.loads(f.read_text(encoding="utf-8"))
    arm, model = d["arm"], d["model"]
    internal = json.loads((RESULTS_DIR / arm / f"{model}_internal.json")
                          .read_text(encoding="utf-8"))["internal_validation"]
    e = d["external_validation"]
    own = (internal["attack_recall"] + internal["benign_recall"]) / 2
    ext = (e["attack_recall"] + e["benign_recall"]) / 2
    rows.append({
        "experiment": "binary", "model": model,
        "trained_on": ARM_NAME[arm], "tested_on": "TRUSTLab",
        "own_data_macro_recall": round(own, 4),
        "external_macro_recall": round(ext, 4),
        "drop": round(own - ext, 4),
        "chance_macro_recall": 0.5,
        "external_family_recall": None,
        "external_roc_auc": round(e["roc_auc"], 4),
        "external_attack_recall": round(e["attack_recall"], 4),
        "external_benign_recall": round(e["benign_recall"], 4),
        "external_accuracy_native_prevalence": round(d["accuracy_native_prevalence"], 4),
    })

mc = json.loads((RESULTS_DIR / "reverse_transfer_mc" / "reverse_transfer_mc.json")
                .read_text(encoding="utf-8"))
for m in mc["models"]:
    for key, name in (("cse", "CSE-CIC-IDS2018"), ("tii", "TII-SSRC-23")):
        own, ext = m[f"{key}_ref"], m[f"{key}_exact"]
        rows.append({
            "experiment": "16-class", "model": m["model"],
            "trained_on": "TRUSTLab", "tested_on": name,
            "own_data_macro_recall": round(own, 4),
            "external_macro_recall": round(ext, 4),
            "drop": round(own - ext, 4),
            "chance_macro_recall": 0.0625,
            "external_family_recall": round(m[f"{key}_family"], 4),
            "external_roc_auc": None, "external_attack_recall": None,
            "external_benign_recall": None,
            "external_accuracy_native_prevalence": None,
        })

df = pd.DataFrame(rows)
out = RESULTS_DIR / "tables" / "11_external_validation_summary.csv"
df.to_csv(out, index=False)
print(df.groupby(["experiment", "tested_on"], sort=False)
        [["own_data_macro_recall", "external_macro_recall", "drop",
          "external_family_recall", "external_roc_auc"]].mean().round(3).to_string())
print(f"\nwrote {out} ({len(df)} rows)")
