# TLS and certificate weakness — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the negotiated protocol version, the cipher suite, the certificate issuer and the validity dates. A downgrade to a deprecated version, or a certificate that does not chain to a trusted issuer, is the finding.

## 4.2 Containment

Disable the deprecated protocol version and cipher suite on the affected service, and replace any certificate that failed validation. Do not disable certificate validation on clients in order to restore connectivity.

## 4.3 Eradication and recovery

Re-test the endpoint and confirm the negotiated parameters have changed. Record the configuration change and its reversal in the incident log.

## 4.4 Distinguishing an attack from a legacy configuration

An old but internally managed service negotiates weak parameters with no adversary present at all. Confirm the endpoint against the service inventory before treating weak negotiation as an attack.
