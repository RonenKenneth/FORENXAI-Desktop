# Command and control — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the destination addresses, the interval between callbacks and how consistent that interval is. Regular timing with low variance is the signal; the volume of data is usually small and is not the indicator.

## 4.2 Containment

Preserve a packet capture of the callbacks before blocking anything, because the block removes the only remaining sample. Then block the destination address and domain at the perimeter and at the resolver, and isolate the source host.

## 4.3 Eradication and recovery

Rebuild the source host from a known-good image. Keep the destination blocked until the implant is confirmed removed. Record the configuration change and its reversal in the incident log.

## 4.4 Distinguishing beaconing from legitimate polling

Software update checks, telemetry agents and monitoring probes also produce regular intervals with small payloads. Confirm the destination against the software inventory before treating regular timing as malicious.
