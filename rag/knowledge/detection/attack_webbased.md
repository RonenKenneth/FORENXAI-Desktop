# WebBased — detection notes

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

Web application attack: injection, cross-site scripting and path traversal against a browser-facing application.

## 1.2 How it appears in flow records

Irregular request intervals across many distinct paths on ports 80 and 443, with variable forward packet lengths reflecting differing payload sizes.

## 1.3 Classes it is confused with

API, because both are application-layer attacks over HTTP that flow records rarely separate. Exploitation, when the payload targets the server rather than the application.

## 1.4 Common false positives

Web vulnerability scanners, security regression suites, and crawlers that probe unusual paths.
