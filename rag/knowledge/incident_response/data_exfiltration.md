# Data exfiltration — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the destination, the total bytes leaving, the protocol used and the time of day. Compare the volume against the normal outbound baseline for that source host before declaring an incident.

## 4.2 Containment

Preserve the flow records and any available payload before blocking. Block the destination at the perimeter and isolate the source host. Do not notify the account holder until the scope of the access is established.

## 4.3 Eradication and recovery

Determine what data was reachable from the source host before returning it to service. Record the configuration change and its reversal in the incident log.

## 4.4 Distinguishing exfiltration from backup and sync traffic

Scheduled backups and cloud file sync also move large volumes outbound on a regular schedule. Confirm the destination against the approved-service list before treating outbound volume as exfiltration.
