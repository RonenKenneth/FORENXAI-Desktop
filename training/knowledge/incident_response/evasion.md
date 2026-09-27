# Detection evasion — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record fragment offsets, TTL values and any overlapping segments. Evasion is inferred from a disagreement between what the sensor reassembles and what the target would reassemble, not from any single field value.

## 4.2 Containment

Enable full reassembly on the sensor before drawing any conclusion from its output, then block the source address at the perimeter. Do not tune the sensor to ignore the pattern: that removes the only detection you have.

## 4.3 Eradication and recovery

Restore normal sensor configuration once the source traffic has stopped, and re-run the stored capture through the reconfigured sensor. Record the configuration change and its reversal in the incident log.

## 4.4 Evasion conceals another technique

Evasion is a wrapper rather than an objective: it is used to deliver something else past a sensor. Identify what the evaded traffic was carrying and respond to that finding as well as to the evasion.
