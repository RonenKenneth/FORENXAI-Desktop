# PortScan — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Network service discovery: enumerating reachable ports and services, usually as a precursor to something else.

## 1.2 How it appears in flow records

Many very short flows from one source to many destination ports, with a high ratio of connections attempted to connections completed and little or no backward payload.

## 1.3 Classes it is confused with

Bruteforce, when the attempts concentrate on one port rather than spread across many.

## 1.4 Common false positives

Authorised vulnerability scanners, asset discovery tooling, load-balancer health checks, and network monitoring sweeps.
