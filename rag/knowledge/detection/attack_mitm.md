# MITM — detection notes

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

Adversary in the middle: ARP or LLMNR poisoning, TCP session hijack and TLS stripping.

## 1.2 How it appears in flow records

Duplicate or changed address-to-hardware bindings on a segment, unexpected certificate issuers, and sessions that downgrade from encrypted to cleartext mid-conversation.

## 1.3 Classes it is confused with

TLSSSL, when the evidence is a certificate or downgrade anomaly rather than a binding change.

## 1.4 Common false positives

Gateway failover, duplicated addresses from a DHCP conflict, transparent proxies, and inspection appliances that legitimately re-sign traffic.
