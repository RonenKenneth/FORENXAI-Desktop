# DNS abuse — detection notes

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

DNS protocol abuse: tunnelling, amplification and cache poisoning.

## 1.2 How it appears in flow records

High query volume on port 53 with long or high-entropy labels for tunnelling, or large responses to small spoofed queries for amplification.

## 1.3 Classes it is confused with

C2Beaconing, when DNS is the callback channel. Exfiltration, when the queries carry encoded payload outbound.

## 1.4 Common false positives

Security products that encode telemetry in DNS, split-horizon resolver misconfiguration, and antivirus reputation lookups.
