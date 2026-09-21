# Evasion — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Detection avoidance: fragment overlap, TTL manipulation, and other techniques that make a sensor reassemble traffic differently from the target.

## 1.2 How it appears in flow records

Inconsistent TTL values within one flow, overlapping fragment offsets, and unusual header lengths relative to payload. The anomaly is in the structure rather than in the volume.

## 1.3 Classes it is confused with

Any class it is wrapping, because evasion carries another technique rather than replacing it.

## 1.4 Common false positives

Path MTU discovery, tunnelling protocols that legitimately fragment, and middleboxes that rewrite headers in transit.
