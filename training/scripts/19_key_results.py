"""
19_key_results.py
-----------------
The study's key machine-learning results in one CSV, read from the stored
results of the GPU run (the tuned, deployed XGBoost; new_deploy_gpu/):

  results/tables/12_key_ml_results.csv

Sections (column "section"):
  binary_internal      15 detectors on held-out data of their own source
  binary_external      the same detectors on TRUSTLab (original run, not the
                       harmonisation check); accuracy and macro F1 also at
                       TRUSTLab's native class mix
  multiclass_internal  five 16-class models on the TRUSTLab test set, plus the
                       XGBoost before tuning
  multiclass_decision  tuned XGBoost with the abstain layer
  multiclass_temporal  XGBoost on a time-ordered split (script 11, a separate
                       run; its random-split row is included for comparison)
  multiclass_external  the five 16-class models on CSE-CIC-IDS2018 and
                       TII-SSRC-23, eight shared classes
  published_baseline   Villafranca et al. (2026), transfer into TRUSTLab

Binary macro F1 is the mean of the attack and benign F1, computed from the
stored confusion matrices. Binary macro recall is the mean of attack and
benign recall. Multi-class macro recall is the mean per-class recall.

Usage:
  python scripts/19_key_results.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import RESULTS_DIR, TRUSTLAB_BASELINE

SRC = {"combined": "CSE-CIC-IDS2018 + TII-SSRC-23", "cicids_only": "CSE-CIC-IDS2018",
       "tii_only": "TII-SSRC-23"}
MODELS = ["XGBoost", "CNN_BiLSTM", "CNN1D", "MLP", "LSTM"]
DEPLOY = RESULTS_DIR.parent / "new_deploy_gpu"


def load(*parts):
    return json.loads(RESULTS_DIR.joinpath(*parts).read_text(encoding="utf-8"))


def from_confusion(c):
    tn, fp, fn, tp = c["tn"], c["fp"], c["fn"], c["tp"]
    n = tn + fp + fn + tp
    f1_attack = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    f1_benign = 2 * tn / (2 * tn + fn + fp) if tn else 0.0
    return {"n_flows": round(n), "accuracy": (tp + tn) / n,
            "macro_f1": (f1_attack + f1_benign) / 2,
            "f1_attack": f1_attack, "f1_benign": f1_benign}


rows = []
for section in ("binary_internal", "binary_external"):
    for arm, name in SRC.items():
        for model in MODELS:
            if section == "binary_internal":
                i = load(arm, f"{model}_internal.json")["internal_validation"]
                rows.append({"section": section, "model": model, "trained_on": name,
                             "evaluated_on": f"{name} (held-out 15%)",
                             **from_confusion(i["confusion"]),
                             "macro_recall": (i["attack_recall"] + i["benign_recall"]) / 2,
                             "attack_recall": i["attack_recall"], "benign_recall": i["benign_recall"],
                             "roc_auc": i["roc_auc"], "pr_auc": i["pr_auc"],
                             "note": "threshold 0.5"})
                continue
            d = load("external", f"{arm}__{model}.json")
            e = d["external_validation"]
            nat = d.get("external_validation_native_prevalence")
            cm_nat = from_confusion(nat["confusion"]) if nat else {}
            rows.append({"section": section, "model": model, "trained_on": name,
                         "evaluated_on": "TRUSTLab test (unseen network)",
                         **from_confusion(e["confusion"]),
                         "accuracy_native_prevalence": cm_nat.get("accuracy"),
                         "macro_f1_native_prevalence": cm_nat.get("macro_f1"),
                         "macro_recall": (e["attack_recall"] + e["benign_recall"]) / 2,
                         "attack_recall": e["attack_recall"], "benign_recall": e["benign_recall"],
                         "roc_auc": e["roc_auc"], "pr_auc": e["pr_auc"],
                         "note": "threshold 0.445; test set 6% benign, native mix ~57% benign"})

for model in MODELS:
    t = load("mc_random", f"{model}_test.json")
    recalls = [v["recall"] for v in t["per_class"].values()]
    rows.append({"section": "multiclass_internal",
                 "model": model + (" (tuned, deployed)" if model == "XGBoost" else ""),
                 "trained_on": "TRUSTLab", "evaluated_on": "TRUSTLab test (280,063 flows)",
                 "n_flows": 280063, "accuracy": t["accuracy"], "macro_f1": t["macro_f1"],
                 "weighted_f1": t["weighted_f1"], "macro_recall": sum(recalls) / len(recalls),
                 "macro_f1_ci_95": f"{t['macro_f1_ci']['ci_low']:.4f}-{t['macro_f1_ci']['ci_high']:.4f}",
                 "note": "random split"})

tune = load("finetune", "xgb_test_comparison_random.json")
rows.append({"section": "multiclass_internal", "model": "XGBoost (initial, before tuning)",
             "trained_on": "TRUSTLab", "evaluated_on": "TRUSTLab test (280,063 flows)",
             "n_flows": tune["test_rows"], "accuracy": tune["acc_old"], "macro_f1": tune["macro_f1_old"],
             "note": (f"tuning gain significant: McNemar p = {tune['mcnemar']['p_value']:.1e}; "
                      f"macro-F1 gain 95% CI {tune['macro_f1_delta_bootstrap95'][0]:+.4f} to "
                      f"{tune['macro_f1_delta_bootstrap95'][1]:+.4f}")})

layer = json.loads((DEPLOY / "decision_thresholds.json").read_text(encoding="utf-8"))["test_measurement"]
w = layer["with_layer"]
rows.append({"section": "multiclass_decision", "model": "XGBoost (tuned) + abstain layer",
             "trained_on": "TRUSTLab", "evaluated_on": "TRUSTLab test, flows kept",
             "accuracy": w["accuracy"], "macro_f1": w["macro_f1"], "abstention_rate": w["abstention_rate"],
             "note": (f"abstained: {w['abstained_low_confidence']:.2%} low confidence, "
                      f"{w['abstained_out_of_distribution']:.2%} out of distribution; error rate "
                      f"{layer['error_rate_kept']:.2%} on kept vs {layer['error_rate_abstained']:.2%} on abstained")})

split = load("session_artifact_analysis.json")["tests"]["split_comparison"]
for kind in ("random", "temporal"):
    rows.append({"section": "multiclass_temporal", "model": "XGBoost (script 11 run)",
                 "trained_on": "TRUSTLab", "evaluated_on": f"TRUSTLab, {kind} split",
                 "accuracy": split[kind]["accuracy"], "macro_f1": split[kind]["macro_f1"],
                 "note": "separate run for the split comparison; the gap between the two rows is the finding"})

rt = load("reverse_transfer_mc", "reverse_transfer_mc.json")
for m in sorted(rt["models"], key=lambda r: MODELS.index(r["model"])):
    for key, name in (("cse", "CSE-CIC-IDS2018"), ("tii", "TII-SSRC-23")):
        rows.append({"section": "multiclass_external", "model": m["model"], "trained_on": "TRUSTLab",
                     "evaluated_on": f"{name} (unseen dataset, 8 shared classes)",
                     "macro_recall": m[f"{key}_exact"], "family_recall": m[f"{key}_family"],
                     "own_data_macro_recall": m[f"{key}_ref"],
                     "note": "exact class; own-data = same classes on the TRUSTLab test set; chance ~0.06"})

b = TRUSTLAB_BASELINE
rows.append({"section": "published_baseline", "model": "DNN experts (Villafranca et al., 2026)",
             "trained_on": "CICIDS2017, UNSW-NB15, BoT-IoT, IoTID20", "evaluated_on": "TRUSTLab",
             "accuracy_native_prevalence": b["accuracy"], "roc_auc": b["roc_auc"],
             "attack_recall": b["attack_recall"], "benign_recall": b["benign_recall"],
             "macro_recall": (b["attack_recall"] + b["benign_recall"]) / 2,
             "note": "published figures, threshold 0.445; different source datasets"})

cols = ["section", "model", "trained_on", "evaluated_on", "n_flows", "accuracy",
        "accuracy_native_prevalence", "macro_f1", "macro_f1_native_prevalence", "macro_f1_ci_95",
        "weighted_f1", "f1_attack", "f1_benign", "macro_recall", "family_recall",
        "own_data_macro_recall", "attack_recall", "benign_recall", "roc_auc", "pr_auc",
        "abstention_rate", "note"]
df = pd.DataFrame(rows).reindex(columns=cols)
num = [c for c in df.select_dtypes("number").columns if c != "n_flows"]
df[num] = df[num].round(4)
df["n_flows"] = df["n_flows"].astype("Int64")
out = RESULTS_DIR / "tables" / "12_key_ml_results.csv"
df.to_csv(out, index=False)
print(f"wrote {out} ({len(df)} rows)")
