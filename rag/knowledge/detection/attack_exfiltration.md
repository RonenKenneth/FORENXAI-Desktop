# Exfiltration — detection notes

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

Data leaving the network over DNS, ICMP, SMTP or chunked HTTP, usually shaped to avoid a volume threshold.

## 1.2 How it appears in flow records

Sustained outbound byte volume with a strongly asymmetric forward-to-backward ratio, often to one destination and often outside working hours.

## 1.3 Classes it is confused with

C2Beaconing, when the same channel carries both. DNS, when DNS is the carrier.

## 1.4 Common false positives

Scheduled backups, cloud file sync, log shipping to a hosted collector, and large legitimate uploads.
