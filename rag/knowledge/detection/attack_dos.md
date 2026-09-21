# DoS — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Single-source resource exhaustion at an intermediate rate, against a service rather than a link.

## 1.2 How it appears in flow records

Sustained flows from one source to one destination port at a rate high enough to consume worker capacity but not the link. Backward volume is low relative to forward volume.

## 1.3 Classes it is confused with

Slowloris. The model cannot reliably separate the two: per-feature SHAP importance correlates at 0.9044 and six of the top ten features are shared. Always report the pair. DDoS, which is the same behaviour from many sources.

## 1.4 Common false positives

A retry storm from a broken client, an unthrottled batch job, and a monitoring check configured at too short an interval.
