# Reconnaissance — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the source address, the ports contacted and the ratio of connections attempted to connections completed. A high attempt-to-completion ratio spread across many ports is the signal.

## 4.2 Containment

Apply rate limiting at the perimeter for the source address and monitor for follow-on connection attempts to any port that responded. Do not block on the basis of a single detection: confirm the source is not an authorised scanner, monitoring probe or health check before applying any block.

## 4.3 Eradication and recovery

Close or firewall any service that responded and was not intended to be reachable from that source. Record the configuration change and its reversal in the incident log.

## 4.4 Reconnaissance is a precursor

Treat a scan that found an open service as the first stage of an incident rather than as an isolated event. Check that service for follow-on activity from the same source within the same capture.
