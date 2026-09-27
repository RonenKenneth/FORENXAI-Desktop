# TLSSSL — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

TLS and SSL weakness or abuse: Heartbleed, POODLE, BEAST and certificate anomalies.

## 1.2 How it appears in flow records

Handshakes negotiating deprecated versions or cipher suites, unusual record sizes relative to the handshake stage, and certificates that do not chain to a trusted issuer.

## 1.3 Classes it is confused with

MITM, when the certificate anomaly is caused by interception rather than by a weak endpoint configuration.

## 1.4 Common false positives

Legacy internal services that were never upgraded, self-signed certificates in a test environment, and pinned internal certificate authorities.
