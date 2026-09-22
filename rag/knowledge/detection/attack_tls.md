# TLSSSL — detection notes

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

TLS and SSL weakness or abuse: Heartbleed, POODLE, BEAST and certificate anomalies.

## 1.2 How it appears in flow records

Handshakes negotiating deprecated versions or cipher suites, unusual record sizes relative to the handshake stage, and certificates that do not chain to a trusted issuer.

## 1.3 Classes it is confused with

MITM, when the certificate anomaly is caused by interception rather than by a weak endpoint configuration.

## 1.4 Common false positives

Legacy internal services that were never upgraded, self-signed certificates in a test environment, and pinned internal certificate authorities.
