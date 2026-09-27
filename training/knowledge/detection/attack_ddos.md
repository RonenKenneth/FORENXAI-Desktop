# DDoS — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

High-rate distributed flooding from many sources against one destination service or link.

## 1.2 How it appears in flow records

A very large number of short flows from many distinct sources to one destination, with high packet rates and low bytes per flow. Backward traffic is minimal or absent where the sources are spoofed.

## 1.3 Classes it is confused with

DoS, which is the same pattern from a single source and is separated mainly by source count rather than by flow shape.

## 1.4 Common false positives

A flash crowd, a scheduled batch job fanning in, and CDN or load-balancer health checks from many edge nodes.
