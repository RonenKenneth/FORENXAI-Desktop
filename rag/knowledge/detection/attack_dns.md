# DNS abuse — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

DNS protocol abuse: tunnelling, amplification and cache poisoning.

## 1.2 How it appears in flow records

High query volume on port 53 with long or high-entropy labels for tunnelling, or large responses to small spoofed queries for amplification.

## 1.3 Classes it is confused with

C2Beaconing, when DNS is the callback channel. Exfiltration, when the queries carry encoded payload outbound.

## 1.4 Common false positives

Security products that encode telemetry in DNS, split-horizon resolver misconfiguration, and antivirus reputation lookups.
