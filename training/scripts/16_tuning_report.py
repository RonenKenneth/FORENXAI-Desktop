"""
16_tuning_report.py
-------------------
Figures and thesis tables for the XGBoost hyperparameter tuning, read from the
two bundles so every number is the stored result, not a recomputation:

    new_deploy_gpu_pre_tune/   the 66-feature XGBoost before tuning
    new_deploy_gpu/            the 66-feature XGBoost after tuning (deployed)

Writes into new_deploy_gpu/:
    figures/fig11_confusion_xgb66_initial.png
    figures/fig12_confusion_xgb66_tuned.png
    figures/fig13_confusion_change_tuned_minus_initial.png
    figures/fig14_system_architecture.png
    thesis_tables_final.md

    python scripts/16_tuning_report.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                  # noqa: E402
from matplotlib.patches import FancyBboxPatch                   # noqa: E402
import numpy as np                                               # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OLD = ROOT / "new_deploy_gpu_pre_tune"
NEW = ROOT / "new_deploy_gpu"
FIG = NEW / "figures"
OUT_MD = NEW / "thesis_tables_final.md"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ----------------------------------------------------------------------
# confusion matrices
# ----------------------------------------------------------------------

def confusion(bundle):
    t = load(bundle / "mc_random_eval" / "XGBoost_test.json")
    cm = np.array(t["confusion_matrix"]["matrix"], dtype=float)
    return t["confusion_matrix"]["labels"], cm, t


def plot_confusion(labels, cm, title, path):
    share = cm / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(11, 9.5))
    im = ax.imshow(share, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(labels)), labels, fontsize=9)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    ax.set_title(title, fontsize=12, pad=12)
    for i in range(len(labels)):
        for j in range(len(labels)):
            v = share[i, j]
            if v >= 0.005:
                ax.text(j, i, f"{v:.2f}\n{int(cm[i, j]):,}", ha="center", va="center",
                        fontsize=6.2, color="white" if v > 0.55 else "#10202f")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.02, label="Share of true class (row-normalised)")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def plot_change(labels, old, new, path):
    delta = (new / new.sum(1, keepdims=True) - old / old.sum(1, keepdims=True)) * 100
    lim = max(1.0, np.abs(delta).max())
    fig, ax = plt.subplots(figsize=(11, 9.5))
    im = ax.imshow(delta, cmap="RdBu", vmin=-lim, vmax=lim)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(labels)), labels, fontsize=9)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    ax.set_title("Change in row-normalised confusion, tuned minus initial (percentage points)\n"
                 "Blue on the diagonal / red off it = improvement", fontsize=11, pad=12)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if abs(delta[i, j]) >= 0.3:
                ax.text(j, i, f"{delta[i, j]:+.1f}", ha="center", va="center", fontsize=7,
                        color="white" if abs(delta[i, j]) > lim * 0.6 else "#10202f")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.02, label="percentage points")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


# ----------------------------------------------------------------------
# system architecture
# ----------------------------------------------------------------------

C = {
    "input": "#dbe7f3", "ml": "#d7ecd9", "xai": "#fbe7c6", "rule": "#f6d5d5",
    "rag": "#e5dcf3", "ui": "#d9e6e4", "edge": "#2b3a46", "planned": "#fff7e0",
}


def box(ax, x, y, w, h, title, body, color, planned=False):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.018",
                           linewidth=1.4, edgecolor=C["edge"], facecolor=color,
                           linestyle="--" if planned else "-")
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.022, title, ha="center", va="top", fontsize=9.2,
            fontweight="bold", color="#10202f")
    ax.text(x + w / 2, y + h - 0.052, body, ha="center", va="top", fontsize=7.2,
            color="#1f2d38", linespacing=1.35)


def arrow(ax, x1, y1, x2, y2, label=""):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", lw=1.3, color=C["edge"]))
    if label:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.014, label, fontsize=6.8, color="#34495a",
                ha="center", va="bottom",
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.9))


def plot_architecture(path):
    fig = plt.figure(figsize=(16, 10.5))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.5, 0.975, "FORENXAI: system architecture", ha="center", va="top",
            fontsize=15, fontweight="bold", color="#10202f")
    ax.text(0.5, 0.948, "Hybrid detection (XGBoost + rule-based Tier 1 / Tier 2 running side by side), "
            "explainability, and grounded recommendations",
            ha="center", va="top", fontsize=9, color="#34495a")

    # input
    box(ax, 0.02, 0.72, 0.15, 0.15, "1  Evidence input",
        "Analyst uploads\n.pcap / .pcapng\nSHA-256 recorded\nCase ID created", C["input"])
    box(ax, 0.21, 0.72, 0.17, 0.15, "2  Flow extraction",
        "CICFlowMeter v4\npcapng -> pcap copy\n84 columns per flow\n(IPs, ports, timestamps)", C["input"])

    # detection column
    box(ax, 0.43, 0.72, 0.2, 0.15, "3a  ML classifier",
        "Tuned XGBoost (66 features)\n132 trees, 16 classes\nscaler + label encoder\nmacro-F1 0.931 (TRUSTLab)", C["ml"])
    box(ax, 0.43, 0.54, 0.2, 0.14, "3b  Rule layer: Tier 1",
        "Flow CSV counts, 60 s windows\nPortScan DDoS DoS Slowloris\nBruteforce C2 Exfiltration\nadjustable rules.json",
        C["rule"])
    box(ax, 0.43, 0.36, 0.2, 0.14, "3c  Rule layer: Tier 2",
        "Raw pcap: Suricata + ET Open\n(WebBased API Exploitation\nBufferOverflow Evasion)\n+ scapy ARP check (MITM)",
        C["rule"])

    # xai
    box(ax, 0.68, 0.72, 0.14, 0.15, "4  TreeSHAP",
        "per-flow drivers\n(66 features, log-odds)\nadditivity < 1e-5", C["xai"])
    box(ax, 0.68, 0.54, 0.14, 0.14, "5  Decision layer",
        "per-class thresholds\nMahalanobis OOD check\n-> Uncertain / abstain", C["xai"])

    # rag
    box(ax, 0.68, 0.19, 0.3, 0.3, "6  Grounded recommendations (RAG)",
        "knowledge_map.py: class -> controls, FOCUS_SECTIONS, playbook\n"
        ".rag_index.json (prebuilt, versioned, reused)\n"
        "NIST SP 800-53 controls + OWASP / RFC / SP 800-52r2 / 800-86\n"
        "SP 800-61r3 3.2, SP 800-86 3.1 + 0-2 retrieved passages\n"
        "inputs: model, SHAP drivers, rule hits + agreement\n"
        "Qwen2.5-3B (local, greedy, JSON grammar, one call at a time)\n"
        "verify_actions(): one supported source per action,\n"
        ">= 2 class-specific actions per attack class", C["rag"])
    box(ax, 0.43, 0.215, 0.2, 0.13, "7  AI-generated summary",
        "facts: prediction, F1, runner-ups,\nSHAP drivers, rule result\nQwen rewords one fact per sentence\nsentence check, else facts as recorded",
        C["rag"])

    # outputs
    box(ax, 0.02, 0.19, 0.36, 0.3, "8  Desktop interface (WPF) and report",
        "Evidence  |  Dashboard  |  XAI  |  Investigation  |  Reports\n\n"
        "XAI view per flow: prediction + confidence, SHAP table,\n"
        "AI-generated summary, Basis panel (Model / SHAP / Rule-based\n"
        "+ agreement badge), recommended actions with citations,\n"
        "verification and ACM references (collapsible)\n\n"
        "Investigator review -> case report (PDF)", C["ui"])
    box(ax, 0.02, 0.03, 0.96, 0.1, "Evaluation and integrity",
        "Leakage-safe splits, internal validation, TRUSTLab external test, reverse transfer  |  "
        "tuning selected on validation, test read once (McNemar p = 1.4e-53)\n"
        "SHA256SUMS over every bundle file  |  RAG index versioned on knowledge/, map, manifest, "
        "SHA256SUMS and builder  |  rules: unit tests, threshold tuning on train, validation, "
        "sensitivity, final test", "#eef2f4")

    # arrows
    arrow(ax, 0.17, 0.795, 0.21, 0.795)
    arrow(ax, 0.38, 0.81, 0.43, 0.81, "flow CSV")
    arrow(ax, 0.36, 0.72, 0.43, 0.63, "flow CSV")
    arrow(ax, 0.30, 0.72, 0.43, 0.44, "raw pcap")
    arrow(ax, 0.63, 0.81, 0.68, 0.81, "class")
    arrow(ax, 0.63, 0.75, 0.68, 0.64, "probabilities")
    arrow(ax, 0.75, 0.72, 0.75, 0.68)
    arrow(ax, 0.79, 0.54, 0.83, 0.49, "verdict + SHAP")
    arrow(ax, 0.63, 0.60, 0.68, 0.43, "rule hits")
    arrow(ax, 0.63, 0.42, 0.68, 0.36, "rule hits")
    arrow(ax, 0.68, 0.28, 0.63, 0.28, "facts")
    arrow(ax, 0.43, 0.28, 0.38, 0.28, "summary")
    arrow(ax, 0.68, 0.2, 0.38, 0.2, "")
    ax.text(0.53, 0.172, "recommendation object (actions, citations, verification)", fontsize=6.8, color="#34495a", ha="center")

    # legend
    items = [("Input", C["input"]), ("ML", C["ml"]), ("Rule layer (Tier 1 / Tier 2)", C["rule"]),
             ("Explainability", C["xai"]), ("RAG + Qwen", C["rag"]), ("Interface", C["ui"])]
    for i, (name, color) in enumerate(items):
        x = 0.03 + i * 0.16
        ax.add_patch(FancyBboxPatch((x, 0.9), 0.018, 0.014, boxstyle="round,pad=0.002",
                                    facecolor=color, edgecolor=C["edge"], lw=0.8))
        ax.text(x + 0.024, 0.907, name, fontsize=7.5, va="center")
    fig.savefig(path, dpi=200)
    plt.close(fig)


# ----------------------------------------------------------------------
# tables
# ----------------------------------------------------------------------

def md(rows, header):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def binary_table():
    names = {"cicids_only": "CSE-CIC-IDS2018", "tii_only": "TII-SSRC-23", "combined": "Combined"}
    rows = []
    for arm in ("combined", "cicids_only", "tii_only"):
        for f in sorted((NEW / "binary_internal" / arm).glob("*_internal.json")):
            d = load(f)
            m, c = d["internal_validation"], d["internal_validation"]["confusion"]
            rows.append([names[arm], d["model"].replace("CNN_BiLSTM", "CNN-BiLSTM"),
                         f"{d['n_train']:,}", f"{sum(c.values()):,}",
                         f"{m['accuracy']:.4f}", f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                         f"{m['f1']:.4f}", f"{m['f2']:.4f}", f"{m['benign_recall']:.4f}",
                         f"{m['false_alarm_rate']:.4f}", f"{m['roc_auc']:.4f}", f"{m['pr_auc']:.4f}",
                         f"{c['tn']:,}", f"{c['fp']:,}", f"{c['fn']:,}", f"{c['tp']:,}"])
    return md(rows, ["Training data", "Model", "Train rows", "Val rows", "Accuracy", "Precision",
                     "Attack recall", "F1", "F2", "Benign recall", "False alarm", "ROC-AUC",
                     "PR-AUC", "TN", "FP", "FN", "TP"])


def main():
    FIG.mkdir(exist_ok=True)
    labels, cm_old, t_old = confusion(OLD)
    labels2, cm_new, t_new = confusion(NEW)
    assert labels == labels2
    plot_confusion(labels, cm_old, "XGBoost, 66 features, initial (400 trees): TRUSTLab test, "
                   f"accuracy {t_old['accuracy']:.4f}, macro-F1 {t_old['macro_f1']:.4f}",
                   FIG / "fig11_confusion_xgb66_initial.png")
    plot_confusion(labels, cm_new, "XGBoost, 66 features, tuned (132 trees): TRUSTLab test, "
                   f"accuracy {t_new['accuracy']:.4f}, macro-F1 {t_new['macro_f1']:.4f}",
                   FIG / "fig12_confusion_xgb66_tuned.png")
    plot_change(labels, cm_old, cm_new, FIG / "fig13_confusion_change_tuned_minus_initial.png")
    plot_architecture(FIG / "fig14_system_architecture.png")

    tu = load(NEW / "finetune" / "xgb_tuning_random.json")
    cmp_ = load(NEW / "finetune" / "xgb_test_comparison_random.json")
    tp = tu["tuned_params"]
    g_old, g_new = load(OLD / "shap_global.json"), load(NEW / "shap_global.json")
    pm = load(NEW / "shap" / "pair_matrix_random.json")
    th_old, th_new = load(OLD / "decision_thresholds.json"), load(NEW / "decision_thresholds.json")
    manifest_old, manifest_new = load(OLD / "manifest.json"), load(NEW / "manifest.json")

    L = ["# Thesis tables -- tuned XGBoost, final set", "",
         "Generated by `scripts/16_tuning_report.py` from `new_deploy_gpu_pre_tune/` (initial) and "
         "`new_deploy_gpu/` (tuned, deployed). Every figure is read from the stored results.", ""]

    # -- binary in-distribution
    L += ["## Table 14 (complete) -- binary detectors, in-distribution validation", "",
          "15% validation split carved from each training configuration, leakage-safe (exact "
          "duplicate flows kept on one side), scaler fitted on the training part only. "
          "Threshold 0.5; positive class = attack. Unchanged by the XGBoost tuning, which "
          "concerns the multiclass model.", "", binary_table(), "",
          "TII-SSRC-23 validation holds only 195 benign flows, so its benign recall and false-alarm "
          "rate rest on very few samples.", ""]

    # -- table 24 up to date
    rows = []
    for f in sorted((NEW / "mc_random_eval").glob("*_test.json")):
        d = load(f)
        rows.append([d["model"].replace("CNN_BiLSTM", "CNN-BiLSTM")
                     + (" (tuned)" if d["model"] == "XGBoost" else ""),
                     f"{d['accuracy']:.4f}", f"{d['macro_f1']:.4f}", f"{d['weighted_f1']:.4f}",
                     f"{d['macro_f1_ci']['ci_low']:.4f}-{d['macro_f1_ci']['ci_high']:.4f}"])
    rows.append(["XGBoost (initial, for reference)", f"{t_old['accuracy']:.4f}",
                 f"{t_old['macro_f1']:.4f}", f"{t_old['weighted_f1']:.4f}",
                 f"{t_old['macro_f1_ci']['ci_low']:.4f}-{t_old['macro_f1_ci']['ci_high']:.4f}"])
    rows.sort(key=lambda r: -float(r[2]))
    L += ["## Table 24 (up to date) -- multiclass model comparison, TRUSTLab test (280,063 flows)", "",
          md([r + [i] for i, r in enumerate(rows, 1)],
             ["Model", "Accuracy", "Macro F1", "Weighted F1", "Macro-F1 95% CI", "Rank"]), ""]

    # -- before / after per class
    rows = []
    for c in labels:
        a, b = t_old["per_class"][c], t_new["per_class"][c]
        rows.append([c, f"{a['precision']:.3f}", f"{b['precision']:.3f}", f"{a['recall']:.3f}",
                     f"{b['recall']:.3f}", f"{a['f1']:.3f}", f"{b['f1']:.3f}",
                     f"{b['f1'] - a['f1']:+.3f}", f"{b['support']:,}"])
    L += ["## Table 24a -- XGBoost per class, initial vs tuned (TRUSTLab test)", "",
          md(rows, ["Class", "Precision (init)", "Precision (tuned)", "Recall (init)", "Recall (tuned)",
                    "F1 (init)", "F1 (tuned)", "F1 change", "Support"]), "",
          f"McNemar on 280,063 test flows: {cmp_['mcnemar']['old_wrong_new_right']:,} corrected, "
          f"{cmp_['mcnemar']['old_right_new_wrong']:,} newly wrong, p = {cmp_['mcnemar']['p_value']:.1e}. "
          f"Bootstrap 95% CI of the macro-F1 gain {cmp_['macro_f1_delta_bootstrap95'][0]:+.4f} to "
          f"{cmp_['macro_f1_delta_bootstrap95'][1]:+.4f}.", "",
          "Confusion matrices: `figures/fig11_confusion_xgb66_initial.png`, "
          "`figures/fig12_confusion_xgb66_tuned.png`, change: "
          "`figures/fig13_confusion_change_tuned_minus_initial.png`.", ""]

    # -- configuration
    rows = [
        ["Boosting rounds", "400 (fixed)", f"{tp['n_estimators']} (early stopping, patience 50, max 3000)"],
        ["max_depth", "10", tp["max_depth"]],
        ["learning_rate", "0.08", f"{tp['learning_rate']:.4f}"],
        ["min_child_weight", "5", f"{tp['min_child_weight']:.3f}"],
        ["subsample", "0.8", f"{tp['subsample']:.3f}"],
        ["colsample_bytree", "0.8", f"{tp['colsample_bytree']:.3f}"],
        ["gamma", "0", f"{tp['gamma']:.3f}"],
        ["reg_alpha (L1)", "0", f"{tp['reg_alpha']:.3f}"],
        ["reg_lambda (L2)", "1", f"{tp['reg_lambda']:.3f}"],
        ["max_bin", "256", tp["max_bin"]],
        ["Class weighting", "balanced", f"balanced x {tp['hard_boost']:.2f} on DoS, Slowloris, Exploitation, BufferOverflow"],
        ["Objective / metric", "multi:softprob / mlogloss", "multi:softprob / mlogloss"],
        ["Tree method / device", "hist / CUDA", "hist / CUDA"],
        ["Features / classes", "66 / 16", "66 / 16"],
        ["Selection", "--", f"Optuna TPE, {tu['trials']} trials, validation macro F1"],
        ["Validation macro F1", f"{tu['val_macro_f1']['baseline']:.4f}", f"{tu['val_macro_f1']['tuned']:.4f}"],
        ["Test accuracy / macro F1", f"{t_old['accuracy']:.4f} / {t_old['macro_f1']:.4f}",
         f"{t_new['accuracy']:.4f} / {t_new['macro_f1']:.4f}"],
    ]
    L += ["## Table 17a -- XGBoost configuration, initial vs tuned", "",
          md(rows, ["Setting", "Initial", "Tuned"]), ""]

    rows = [[c, th_old["per_class_threshold"][c], th_new["per_class_threshold"][c]] for c in labels]
    wo_o, wi_o = th_old["test_measurement"]["without_layer"], th_old["test_measurement"]["with_layer"]
    wo_n, wi_n = th_new["test_measurement"]["without_layer"], th_new["test_measurement"]["with_layer"]
    L += ["## Table 17b -- decision layer refitted to the tuned model", "",
          "Per-class confidence thresholds are chosen on the validation split; they were refitted "
          "because the tuned model's probabilities differ. The OOD statistics depend only on the "
          "scaler and are unchanged.", "",
          md(rows, ["Class", "Threshold (initial)", "Threshold (tuned)"]), "",
          md([["Accuracy without layer", f"{wo_o['accuracy']:.4f}", f"{wo_n['accuracy']:.4f}"],
              ["Macro F1 without layer", f"{wo_o['macro_f1']:.4f}", f"{wo_n['macro_f1']:.4f}"],
              ["Accuracy on kept flows", f"{wi_o['accuracy']:.4f}", f"{wi_n['accuracy']:.4f}"],
              ["Macro F1 on kept flows", f"{wi_o['macro_f1']:.4f}", f"{wi_n['macro_f1']:.4f}"],
              ["Abstained", f"{wi_o['abstention_rate']:.2%}", f"{wi_n['abstention_rate']:.2%}"],
              ["  low confidence", f"{wi_o['abstained_low_confidence']:.2%}", f"{wi_n['abstained_low_confidence']:.2%}"],
              ["  out of distribution", f"{wi_o['abstained_out_of_distribution']:.2%}", f"{wi_n['abstained_out_of_distribution']:.2%}"],
              ["Error rate on abstained flows", f"{th_old['test_measurement']['error_rate_abstained']:.2%}",
               f"{th_new['test_measurement']['error_rate_abstained']:.2%}"]],
             ["Measure (TRUSTLab test)", "Initial", "Tuned"]), ""]

    # -- SHAP configuration
    def shapcfg(g):
        return [g["n_sample"], g["n_features"], g["units"], g["feature_perturbation"],
                g["attribution_device"], f"{g['additivity_max_error']:.2e}",
                f"{g['additivity_tolerance']:.0e}", f"{g['reconstruction_picks_predicted']:.3f}",
                f"{g['shown_share_of_total']:.3f}", len(g.get("unused_features", []))]
    names = ["Sampled test flows (500 per class)", "Features", "Units", "Feature perturbation",
             "Device", "Additivity max error", "Additivity tolerance",
             "Reconstruction picks the predicted class", "Share of absolute SHAP carried by the features shown",
             "Features never used by the trees"]
    L += ["## Table 27a -- TreeSHAP configuration and checks, initial vs tuned model", "",
          md([[n, a, b] for n, a, b in zip(names, shapcfg(g_old), shapcfg(g_new))],
             ["Item", "Initial", "Tuned"]), "",
          f"The tuned booster holds exactly {tp['n_estimators']} trees, so TreeExplainer and "
          "predict() use the same model.", ""]

    # -- SHAP per class (tuned) + change
    def top(g, c, k):
        return sorted(g["per_class_own"][c], key=lambda x: -x["mean_abs_shap"])[:k]
    feats = sorted({x["feature"] for c in g_new["per_class_own"] for x in g_new["per_class_own"][c]})

    def vec(g, c):
        d = {x["feature"]: x["mean_abs_shap"] for x in g["per_class_own"][c]}
        return np.array([d.get(f, 0.0) for f in feats])
    rows = [[c] + [f"{x['feature']} ({x['mean_abs_shap']:.2f})" for x in top(g_new, c, 6)] for c in labels]
    L += ["## Table 28 (tuned) -- per-class attribution, six leading features", "",
          "Mean |SHAP| in log-odds over the sampled flows whose true class is the row's class.", "",
          md(rows, ["Attack class"] + [f"Rank {i} feature (mean |SHAP|)" for i in range(1, 7)]), ""]
    rows, same = [], 0
    for c in labels:
        o, n = top(g_old, c, 6), top(g_new, c, 6)
        same += o[0]["feature"] == n[0]["feature"]
        rows.append([c, o[0]["feature"], n[0]["feature"],
                     f"{len({x['feature'] for x in o} & {x['feature'] for x in n})} / 6",
                     f"{np.corrcoef(vec(g_old, c), vec(g_new, c))[0, 1]:.3f}"])
    L += ["## Table 28b -- how the SHAP explanation changed with tuning", "",
          md(rows, ["Class", "Top feature (initial)", "Top feature (tuned)", "Top-6 overlap",
                    "Correlation of mean absolute SHAP"]), "",
          f"The leading feature is unchanged for {same} of 16 classes.", ""]

    share = cm_new / cm_new.sum(1, keepdims=True)
    idx = {c: i for i, c in enumerate(labels)}
    pairs = []
    for rank, p in enumerate(pm["pairs"], 1):
        conf = max(share[idx[p["a"]], idx[p["b"]]], share[idx[p["b"]], idx[p["a"]]])
        pairs.append((rank, p["a"], p["b"], p["corr"], p["shared_top10"], conf))
    sel = sorted([x for x in pairs if x[5] > 0.01], key=lambda x: -x[5])
    if not any(x[0] == 1 for x in sel):
        sel.append(pairs[0])
    L += ["## Table 30 (tuned) -- attribution overlap and observed confusion", "",
          md([[r, f"{a} / {b}", f"{co:.3f}", f"{sh} / 10", f"{cf:.1%}"] for r, a, b, co, sh, cf in sel],
             ["Similarity rank (of 120)", "Class pair", "Importance correlation", "Shared top-10",
              "Confusion"]), "",
          f"Of the 120 pairs, {sum(1 for x in pairs if x[5] == 0)} are never confused.", ""]

    # -- bundle inventory
    def sha(m, name):
        entry = m["files"].get(name, {})
        return (entry.get("sha256_16") or entry.get("sha256", "")[:16]).lower()
    inv = [
        ["XGBoost.pkl", "16-class classifier", "replaced (tuned)", sha(manifest_old, "XGBoost.pkl"), sha(manifest_new, "XGBoost.pkl")],
        ["scaler.pkl", "StandardScaler, training rows only", "unchanged", sha(manifest_old, "scaler.pkl"), sha(manifest_new, "scaler.pkl")],
        ["features.pkl", "66 feature names, in order", "unchanged", sha(manifest_old, "features.pkl"), sha(manifest_new, "features.pkl")],
        ["label_encoder.pkl", "16 class names", "unchanged", sha(manifest_old, "label_encoder.pkl"), sha(manifest_new, "label_encoder.pkl")],
        ["shap_global.json", "per_class and per_class_own attribution", "regenerated", sha(manifest_old, "shap_global.json"), sha(manifest_new, "shap_global.json")],
        ["manifest.json", "hashes, feature order, versions", "regenerated", "", ""],
        ["decision_thresholds.json", "per-class abstention thresholds", "refitted", "", ""],
        ["ood_stats.json", "Mahalanobis OOD statistics", "unchanged", "", ""],
        ["shap/", "global, pair matrix, examples", "regenerated", "", ""],
        ["mc_random_eval/XGBoost_*", "test and validation results", "regenerated", "", ""],
        ["mc_summary_random_gpu.csv, mc_per_class_random_gpu.csv", "model summaries", "regenerated", "", ""],
        ["reverse_transfer_mc/", "external transfer of the multiclass models", "regenerated", "", ""],
        ["tables/03, 07, 08, 09", "vs published, feature inventory, confusion", "regenerated", "", ""],
        ["figures/fig1, 2, 4, 5, 10", "paper figures", "regenerated", "", ""],
        ["figures/fig11-14", "confusion before/after, change, architecture", "new", "", ""],
        ["finetune/", "tuning record: VALIDATION.md, trials, test comparison, script", "new", "", ""],
        ["thesis_table_24a.md, thesis_tables_tuned.md, thesis_tables_final.md", "tables", "new", "", ""],
        ["binary_internal/, external_eval/, phase2_random/", "binary experiment, Phase 2", "unchanged", "", ""],
        ["SHA256SUMS.txt (+ .sha256)", "hash of every bundle file", "regenerated", "", ""],
    ]
    L += ["## Bundle inventory -- what the tuning changed (new_deploy_gpu/)", "",
          md(inv, ["File", "Role", "Status", "SHA-256/16 initial", "SHA-256/16 tuned"]), "",
          "The previous versions of every changed file are in `new_deploy_gpu_pre_tune/`. The desktop "
          "application ships XGBoost.pkl, scaler.pkl, features.pkl, label_encoder.pkl, "
          "shap_global.json, manifest.json and model_facts.json (branch finetuned-xgboost).", ""]

    L += ["## Figures", "",
          md([["fig11_confusion_xgb66_initial.png", "Confusion matrix, initial XGBoost (row-normalised share and count)"],
              ["fig12_confusion_xgb66_tuned.png", "Confusion matrix, tuned XGBoost"],
              ["fig13_confusion_change_tuned_minus_initial.png", "Change in row-normalised confusion, percentage points"],
              ["fig14_system_architecture.png", "Complete system architecture incl. rule layer Tier 1 and Tier 2"]],
             ["File (new_deploy_gpu/figures/)", "Content"]), ""]

    OUT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("wrote", OUT_MD)
    export_csv(OUT_MD.read_text(encoding="utf-8"))
    for f in ("fig11_confusion_xgb66_initial.png", "fig12_confusion_xgb66_tuned.png",
              "fig13_confusion_change_tuned_minus_initial.png", "fig14_system_architecture.png"):
        print("wrote", FIG / f)


# Each table of thesis_tables_final.md as its own CSV in tables/.
CSV_NAMES = {
    "Table 14 (complete)": ["T14_binary_in_distribution_validation.csv"],
    "Table 24 (up to date)": ["T24_multiclass_model_comparison.csv"],
    "Table 24a": ["T24a_xgboost_per_class_initial_vs_tuned.csv"],
    "Table 17a": ["T17a_xgboost_configuration_initial_vs_tuned.csv"],
    "Table 17b": ["T17b_decision_thresholds_initial_vs_tuned.csv",
                  "T17b_decision_layer_test_effect.csv"],
    "Table 27a": ["T27a_treeshap_configuration_initial_vs_tuned.csv"],
    "Table 28 (tuned)": ["T28_shap_top6_features_per_class_tuned.csv"],
    "Table 28b": ["T28b_shap_change_initial_vs_tuned.csv"],
    "Table 30 (tuned)": ["T30_shap_overlap_vs_confusion_tuned.csv"],
    "Bundle inventory": ["bundle_inventory_tuning.csv"],
}


def export_csv(markdown):
    import csv
    import re
    for section in re.split(r"\n## ", markdown)[1:]:
        title = section.split("\n", 1)[0]
        key = next((k for k in CSV_NAMES if title.startswith(k)), None)
        if not key:
            continue
        tables, current = [], []
        for line in section.splitlines():
            if line.startswith("|"):
                current.append(line)
            elif current:
                tables.append(current)
                current = []
        if current:
            tables.append(current)
        assert len(tables) == len(CSV_NAMES[key]), (key, len(tables))
        for rows, name in zip(tables, CSV_NAMES[key]):
            cells = [[c.strip() for c in r.strip().strip("|").split("|")]
                     for r in rows if not re.match(r"^\|(-+\|)+$", r.strip())]
            assert len({len(c) for c in cells}) == 1, f"ragged table {name}"
            with open(NEW / "tables" / name, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(cells)
            print("wrote", NEW / "tables" / name)


if __name__ == "__main__":
    main()
