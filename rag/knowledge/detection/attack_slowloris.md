# Slowloris — detection notes

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

Low-and-slow connection exhaustion: many half-open requests held for a long time to consume worker slots without generating volume.

## 1.2 How it appears in flow records

Long flow durations with very low byte counts and large minimum inter-arrival times. `Flow IAT Min` is high because the client deliberately waits between partial requests, which is the opposite shape to a flood.

## 1.3 Classes it is confused with

DoS. The model cannot reliably separate the two: per-feature SHAP importance correlates at 0.9159 and seven of the top ten features are shared. Report both sub-types rather than choosing one.

## 1.4 Common false positives

Clients on high-latency links, long-polling and server-sent-event connections, and idle keep-alive sessions from a mobile network.
