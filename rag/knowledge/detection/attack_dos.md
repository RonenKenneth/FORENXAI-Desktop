# DoS — detection notes

> **Provenance.** This file describes how the class appears in the
> TRUSTLab flow records this model was trained on. It is the
> project's own analysis, not an extract from a standard, because no
> standard describes how an attack looks in CICFlowMeter features.
> Any figure quoted below is reproduced from `results/` and can be
> checked there: SHAP correlations from
> `shap/pair_matrix_random.json`, confusion rates from
> `tables/09_confusion_XGBoost_rownorm.csv`. The false-positive
> notes are analyst judgement and should be reviewed against your
> own traffic.
>
> Response guidance is not here: it is in
> `../incident_response/`, compiled from the cited publications.
> Keep the heading structure intact -- retrieval depends on it.

## 1.1 What this class covers

Single-source resource exhaustion at an intermediate rate, against a service rather than a link.

## 1.2 How it appears in flow records

Sustained flows from one source to one destination port at a rate high enough to consume worker capacity but not the link. Backward volume is low relative to forward volume.

## 1.3 Classes it is confused with

Slowloris. The model cannot reliably separate the two: per-feature SHAP importance correlates at 0.9159 and seven of the top ten features are shared. Always report the pair. DDoS, which is the same behaviour from many sources.

## 1.4 Common false positives

A retry storm from a broken client, an unthrottled batch job, and a monitoring check configured at too short an interval.
