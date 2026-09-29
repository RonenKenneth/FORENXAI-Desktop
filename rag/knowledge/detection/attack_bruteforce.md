# Bruteforce — detection notes

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

Repeated authentication attempts against a service, either many attempts against one account or few attempts across many accounts.

## 1.2 How it appears in flow records

Many short flows to one destination port with near-identical forward packet lengths and short, regular inter-arrival times. Flow durations cluster tightly because each attempt is the same exchange.

## 1.3 Classes it is confused with

Exploitation, where repeated connection attempts to one service look similar in flow records. PortScan, when the attempts spread across ports rather than accounts.

## 1.4 Common false positives

A misconfigured client retrying a stale credential, an expired service account, and load-test tooling against an authentication endpoint.
