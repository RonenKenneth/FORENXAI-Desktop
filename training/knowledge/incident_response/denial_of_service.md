# Denial of service — response

> **PLACEHOLDER.** Written to exercise the citation-verification path, not
> sourced from any standard. Replace with the relevant sections of NIST
> SP 800-61r3 and your own runbook before this is used on real traffic.
> Keep the heading structure intact: the retrieval and quote-verification
> steps depend on it.

## 4.1 Detection and analysis

Record the source addresses, the destination service, and the request rate.
Establish whether the traffic volume exceeds the normal baseline for that
service before declaring an incident.

Distinguish resource exhaustion from bandwidth exhaustion. A service that is
unresponsive while the link is not saturated indicates connection or worker
exhaustion rather than flooding.

## 4.2 Containment

Apply rate limiting at the perimeter for the identified source addresses.
Where the source set is large or spoofed, apply rate limiting by
destination service rather than by source.

Increase the connection timeout floor and reduce the maximum keep-alive
duration on the affected service. This is the specific mitigation for
connection-holding attacks that consume worker slots without generating
volume.

Do not block on the basis of a single detection. Confirm the source is not an
authorised scanner, monitoring probe, or health check before applying any
block.

## 4.3 Eradication and recovery

Restore normal timeout and rate-limit configuration once the source traffic
has stopped for a sustained period. Record the configuration change and its
reversal in the incident log.

## 4.4 Distinguishing slow-rate from high-rate

Slow-rate attacks hold many connections open with minimal traffic per
connection; high-rate attacks generate large volumes across shorter
connections. The mitigations differ: slow-rate is addressed by timeout and
per-source connection limits, high-rate by rate limiting and upstream
filtering.

Where the two cannot be distinguished from flow records alone, apply the
slow-rate mitigations first, since they are lower impact on legitimate
traffic.
