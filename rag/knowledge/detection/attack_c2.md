# C2Beaconing — detection notes

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

Periodic callbacks from a compromised host to a controller over HTTP, HTTPS, DNS, IRC, MQTT or WebSocket.

## 1.2 How it appears in flow records

Low-variance inter-arrival times across repeated small flows to a single destination. The regularity of the interval carries the signal; the byte volume is small and does not.

## 1.3 Classes it is confused with

DNS, when the callback channel is DNS. Exfiltration, when the callbacks carry data outbound rather than instructions inbound.

## 1.4 Common false positives

Software update checks, telemetry agents, monitoring probes and NTP: all produce regular low-volume callbacks to a fixed destination.
