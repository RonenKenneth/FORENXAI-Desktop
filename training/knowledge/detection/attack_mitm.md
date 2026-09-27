# MITM — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Adversary in the middle: ARP or LLMNR poisoning, TCP session hijack and TLS stripping.

## 1.2 How it appears in flow records

Duplicate or changed address-to-hardware bindings on a segment, unexpected certificate issuers, and sessions that downgrade from encrypted to cleartext mid-conversation.

## 1.3 Classes it is confused with

TLSSSL, when the evidence is a certificate or downgrade anomaly rather than a binding change.

## 1.4 Common false positives

Gateway failover, duplicated addresses from a DHCP conflict, transparent proxies, and inspection appliances that legitimately re-sign traffic.
