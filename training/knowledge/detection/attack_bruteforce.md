# Bruteforce — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Repeated authentication attempts against a service, either many attempts against one account or few attempts across many accounts.

## 1.2 How it appears in flow records

Many short flows to one destination port with near-identical forward packet lengths and short, regular inter-arrival times. Flow durations cluster tightly because each attempt is the same exchange.

## 1.3 Classes it is confused with

Exploitation, where repeated connection attempts to one service look similar in flow records. PortScan, when the attempts spread across ports rather than accounts.

## 1.4 Common false positives

A misconfigured client retrying a stale credential, an expired service account, and load-test tooling against an authentication endpoint.
