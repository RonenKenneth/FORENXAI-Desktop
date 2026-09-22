# DDoS — detection notes

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

High-rate distributed flooding from many sources against one destination service or link.

## 1.2 How it appears in flow records

A very large number of short flows from many distinct sources to one destination, with high packet rates and low bytes per flow. Backward traffic is minimal or absent where the sources are spoofed.

## 1.3 Classes it is confused with

DoS, which is the same pattern from a single source and is separated mainly by source count rather than by flow shape.

## 1.4 Common false positives

A flash crowd, a scheduled batch job fanning in, and CDN or load-balancer health checks from many edge nodes.
