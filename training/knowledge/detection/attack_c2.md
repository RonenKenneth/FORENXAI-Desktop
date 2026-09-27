# C2Beaconing — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Periodic callbacks from a compromised host to a controller over HTTP, HTTPS, DNS, IRC, MQTT or WebSocket.

## 1.2 How it appears in flow records

Low-variance inter-arrival times across repeated small flows to a single destination. The regularity of the interval carries the signal; the byte volume is small and does not.

## 1.3 Classes it is confused with

DNS, when the callback channel is DNS. Exfiltration, when the callbacks carry data outbound rather than instructions inbound.

## 1.4 Common false positives

Software update checks, telemetry agents, monitoring probes and NTP: all produce regular low-volume callbacks to a fixed destination.
