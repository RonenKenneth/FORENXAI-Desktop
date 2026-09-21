# Exfiltration — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Data leaving the network over DNS, ICMP, SMTP or chunked HTTP, usually shaped to avoid a volume threshold.

## 1.2 How it appears in flow records

Sustained outbound byte volume with a strongly asymmetric forward-to-backward ratio, often to one destination and often outside working hours.

## 1.3 Classes it is confused with

C2Beaconing, when the same channel carries both. DNS, when DNS is the carrier.

## 1.4 Common false positives

Scheduled backups, cloud file sync, log shipping to a hosted collector, and large legitimate uploads.
