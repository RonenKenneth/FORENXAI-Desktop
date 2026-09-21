# Adversary in the middle — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the claimed and observed address-to-hardware bindings, the certificate presented and any protocol downgrade. A changed binding or an unexpected certificate issuer is the indicator; traffic volume is not.

## 4.2 Containment

Record the current address tables before clearing anything, then isolate the source of the poisoned responses from the segment. Enable dynamic address inspection or the equivalent control on that segment.

## 4.3 Eradication and recovery

Rotate any credentials that traversed the affected segment during the window. Restore normal segment configuration and record the change and its reversal in the incident log.

## 4.4 Distinguishing an attack from a misconfiguration

A failed-over gateway, a duplicated address and a transparent proxy all produce the same binding changes as an attack. Confirm the device inventory before treating a changed binding as hostile.
