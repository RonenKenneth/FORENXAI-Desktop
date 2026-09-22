# API abuse — detection notes

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

Abuse of REST, GraphQL or SOAP endpoints: mass assignment, injection, XXE and authorisation bypass against a machine-facing interface.

## 1.2 How it appears in flow records

Regular, machine-timed request intervals against a small set of destination ports, with consistent forward packet sizes. `Dst Port` is usually the strongest single feature, which is also the reason to be careful with it.

## 1.3 Classes it is confused with

WebBased, because both are application-layer attacks over HTTP and the flow records rarely separate them. Exploitation, where the payload targets the server rather than the application.

## 1.4 Common false positives

API test suites, contract tests and synthetic monitoring generate the same regular machine-timed pattern against the same endpoints.
