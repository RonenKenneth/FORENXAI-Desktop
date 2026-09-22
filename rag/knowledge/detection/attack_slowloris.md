# Slowloris — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Low-and-slow connection exhaustion: many half-open requests held for a long time to consume worker slots without generating volume.

## 1.2 How it appears in flow records

Long flow durations with very low byte counts and large minimum inter-arrival times. `Flow IAT Min` is high because the client deliberately waits between partial requests, which is the opposite shape to a flood.

## 1.3 Classes it is confused with

DoS. The model cannot reliably separate the two: per-feature SHAP importance correlates at 0.9159 and seven of the top ten features are shared. Report both sub-types rather than choosing one.

## 1.4 Common false positives

Clients on high-latency links, long-polling and server-sent-event connections, and idle keep-alive sessions from a mobile network.
