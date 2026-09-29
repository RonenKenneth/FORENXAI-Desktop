# BufferOverflow — detection notes

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

Memory-corruption exploitation against a listening service: oversized or malformed input intended to overwrite adjacent memory.

## 1.2 How it appears in flow records

A small number of flows carrying unusually large forward packets to a service port, often followed by a connection reset or by new outbound activity from the target.

## 1.3 Classes it is confused with

Exploitation. A substantial share of BufferOverflow flows are predicted as Exploitation, and the reverse happens less often; the measured rate in each direction is reported with the finding. Both are exploitation of a listening service and the response overlaps, so the two are flagged as an ambiguous pair and reported together. The pair shares little evidence, so the confusion is not explained by shared features.

## 1.4 Common false positives

Legitimate large uploads, file transfer over a non-standard port, and protocol fuzzing run by an authorised tester.
