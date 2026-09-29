"""
Evaluation metrics for binary flow classification.

Label convention throughout: 0 = Benign, 1 = Attack.

F2 is reported alongside F1 because the published TRUSTLab baseline reports
it, and comparing like with like requires it. F2 weights recall above
precision, which suits intrusion detection where a missed attack usually
costs more than a false alarm.

Benign recall is called out separately because it is the most diagnostic
single number in this experiment. The training data is attack-heavy, so a
model that has not learned what normal traffic looks like will show high
attack recall and poor benign recall -- and the aggregate accuracy can hide
that entirely.
"""
import numpy as np
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, fbeta_score, roc_auc_score,
                             average_precision_score, confusion_matrix,
                             classification_report)


def binary_metrics(y_true, y_pred, y_score=None, sample_weight=None):
    """y_score is the predicted probability of class 1 (Attack), if available.

    sample_weight reweights every figure to a different population. Script 06
    uses it to score the capped TRUSTLab test set at the corpus's real class
    prevalence: accuracy is not the only metric that moves with prevalence --
    precision, F1 and F2 move with it too, so correcting accuracy alone and
    printing the rest beside the published baseline compares two different
    populations on four of the five columns.
    """
    sw = None if sample_weight is None else np.asarray(sample_weight, float)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1],
                                      sample_weight=sw).ravel()

    out = {
        "accuracy":  float(accuracy_score(y_true, y_pred, sample_weight=sw)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0,
                                           sample_weight=sw)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0,
                                        sample_weight=sw)),
        "f1":        float(f1_score(y_true, y_pred, zero_division=0,
                                    sample_weight=sw)),
        "f2":        float(fbeta_score(y_true, y_pred, beta=2, zero_division=0,
                                       sample_weight=sw)),
        "benign_recall": float(tn / (tn + fp)) if (tn + fp) else 0.0,
        "attack_recall": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "false_alarm_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "miss_rate":        float(fn / (fn + tp)) if (fn + tp) else 0.0,
        # Weighted cells are effective counts in the target population, so
        # they are fractional before rounding.
        "confusion": {"tn": int(round(tn)), "fp": int(round(fp)),
                      "fn": int(round(fn)), "tp": int(round(tp))},
    }

    if y_score is not None:
        try:
            out["roc_auc"] = float(roc_auc_score(y_true, y_score,
                                                 sample_weight=sw))
            out["pr_auc"] = float(average_precision_score(y_true, y_score,
                                                          sample_weight=sw))
        except ValueError:
            # raised when y_true contains only one class
            out["roc_auc"] = None
            out["pr_auc"] = None

    return out


def compare_to_baseline(metrics, baseline):
    """Signed difference against the published figures."""
    keys = ["accuracy", "f2", "roc_auc", "attack_recall", "benign_recall"]
    return {k: round(metrics[k] - baseline[k], 4)
            for k in keys
            if metrics.get(k) is not None and baseline.get(k) is not None}


def report_text(y_true, y_pred):
    return classification_report(y_true, y_pred, digits=4, zero_division=0,
                                 target_names=["Benign", "Attack"])


def threshold_sweep(y_true, y_score, thresholds=None):
    """
    Performance across decision thresholds.

    The default 0.5 is rarely optimal. TRUSTLab's baseline used 0.445, chosen
    slightly above the F2-maximising point to reduce false alarms -- so
    comparing a 0.5-threshold model against their figure is not quite
    like-for-like. This sweep makes the trade-off visible.
    """
    if thresholds is None:
        thresholds = [0.05, 0.1, 0.2, 0.3, 0.4, 0.445, 0.5,
                      0.6, 0.7, 0.8, 0.9]
    rows = []
    y_score = np.asarray(y_score)
    for t in thresholds:
        m = binary_metrics(y_true, (y_score >= t).astype(int))
        rows.append({
            "threshold": t,
            "accuracy": round(m["accuracy"], 4),
            "f1": round(m["f1"], 4),
            "f2": round(m["f2"], 4),
            "attack_recall": round(m["attack_recall"], 4),
            "benign_recall": round(m["benign_recall"], 4),
            "false_alarm_rate": round(m["false_alarm_rate"], 4),
        })
    return rows


def per_class_accuracy(y_true, y_pred, group_labels):
    """
    Accuracy broken down by original attack family.

    Useful on TRUSTLab because it shows which families transfer and which do
    not -- an aggregate figure hides the fact that some attack types may be
    detected almost perfectly while others fail completely.
    """
    out = {}
    group_labels = np.asarray(group_labels)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    for g in sorted(set(group_labels)):
        m = group_labels == g
        if m.sum() == 0:
            continue
        out[str(g)] = {"n": int(m.sum()),
                       "accuracy": round(float((y_pred[m] == y_true[m]).mean()), 4)}
    return out


def per_class_f1_ci(y_true, y_pred, n_classes, macro_over=None,
                    n_boot=2000, alpha=0.05, seed=42):
    """
    Bootstrap confidence intervals for per-class F1, and for the macro average.

    WHY THIS IS NEEDED
    An F1 printed to four decimals looks equally solid whether it rests on
    fifteen thousand test flows or on seven, and nothing in the number itself
    says which. In the Phase-2 runs a filter upstream decides how much of each
    class survives to be scored, so support varies by three orders of
    magnitude inside a single table: Bruteforce scored 0.8571 on seven flows,
    which is six right out of seven, and moved 0.09 between two thresholds
    because one flow changed. A reader cannot tell that from a real effect
    without an interval. A hand-written list of "classes solid enough to
    quote" would be a judgement made once against one run, and stale the
    moment a threshold, cap or split changed; an interval is recomputed from
    the data every time and cannot go stale.

    WHY THIS IS EXACT AND NOT AN APPROXIMATION
    The nonparametric bootstrap resamples the test set with replacement and
    recomputes the statistic. F1 depends on the data only through the
    confusion matrix, so resampling n rows is exactly equivalent to drawing
    the matrix's cell counts from Multinomial(n, p), with p the observed cell
    proportions. This is not a shortcut that approximates the bootstrap -- it
    is the same distribution, evaluated in O(n_boot * n_classes^2) rather than
    O(n_boot * n). At 235,000 flows and 2,000 resamples that is seconds
    instead of many minutes, which is what makes it affordable on every class
    of every rung.

    macro_over: class indices to average for the macro interval. Pass the
    classes that actually have support -- averaging in a class with none
    measures the filter in front of the model, not the model.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    k = int(n_classes)

    counts = np.bincount(y_true * k + y_pred, minlength=k * k).astype(float)
    n = int(counts.sum())
    out = {"per_class": {}, "macro": None, "n_boot": int(n_boot),
           "alpha": float(alpha), "n": n}
    if n == 0:
        return out

    rng = np.random.default_rng(seed)
    draws = rng.multinomial(n, counts / n, size=int(n_boot))
    draws = draws.reshape(int(n_boot), k, k).astype(float)

    tp = np.einsum("bii->bi", draws)      # diagonal: true positives
    true_n = draws.sum(axis=2)            # row sums: actual support
    pred_n = draws.sum(axis=1)            # column sums: predictions made
    denom = true_n + pred_n               # F1 = 2TP / (support + predicted)
    f1 = np.where(denom > 0, 2.0 * tp / np.maximum(denom, 1.0), 0.0)

    lo_q, hi_q = 100 * alpha / 2, 100 * (1 - alpha / 2)
    lo, hi = np.percentile(f1, lo_q, axis=0), np.percentile(f1, hi_q, axis=0)
    for i in range(k):
        sup = int((y_true == i).sum())
        out["per_class"][i] = {
            "support": sup,
            "ci_low": float(lo[i]) if sup else None,
            "ci_high": float(hi[i]) if sup else None,
            "ci_width": float(hi[i] - lo[i]) if sup else None,
        }

    idx = list(macro_over) if macro_over is not None else list(range(k))
    if idx:
        macro = f1[:, idx].mean(axis=1)
        out["macro"] = {"ci_low": float(np.percentile(macro, lo_q)),
                        "ci_high": float(np.percentile(macro, hi_q))}
    return out
