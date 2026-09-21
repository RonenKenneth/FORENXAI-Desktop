# Web application attack — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the request path, the method, the source address and the response codes the application returned. Establish whether the requests reached the application or were rejected at the proxy before declaring an incident. A rejected request is an attempt; a 200 response to an injection payload is an incident.

## 4.2 Containment

Apply request rate limiting per source address at the reverse proxy. Where the payload is identifiable, add a blocking rule for that pattern rather than for the source address, because source addresses rotate and the pattern usually does not. Take a copy of the application logs before making any configuration change.

## 4.3 Eradication and recovery

Fix or patch the vulnerable endpoint before removing the blocking rule. Re-test the endpoint with the original request and confirm it is now rejected. Record the configuration change and its reversal in the incident log.

## 4.4 Distinguishing API abuse from browser-driven attacks

API abuse shows regular, machine-timed intervals against a small set of endpoints. Browser-driven attacks show irregular intervals across many paths and carry browser-shaped headers. Where the two cannot be separated from flow records alone, apply the rate limit at the endpoint rather than at the source, since that is correct for both.
