# PortScan — detection notes

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

Network service discovery: enumerating reachable ports and services, usually as a precursor to something else.

## 1.2 How it appears in flow records

Many very short flows from one source to many destination ports, with a high ratio of connections attempted to connections completed and little or no backward payload.

## 1.3 Classes it is confused with

Bruteforce, when the attempts concentrate on one port rather than spread across many.

## 1.4 Common false positives

Authorised vulnerability scanners, asset discovery tooling, load-balancer health checks, and network monitoring sweeps.
