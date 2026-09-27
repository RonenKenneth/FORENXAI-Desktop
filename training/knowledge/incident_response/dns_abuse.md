# DNS abuse — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the query names, the query types, the rate and the resolver used. A high query volume to a single domain with long or high-entropy labels indicates tunnelling rather than ordinary resolution.

## 4.2 Containment

Preserve the resolver query logs before making any change. Block the domain at the resolver, force clients to the internal resolver, and apply per-source query rate limiting.

## 4.3 Eradication and recovery

Restore normal resolver configuration once the source traffic has stopped for a sustained period. Record the configuration change and its reversal in the incident log.

## 4.4 Distinguishing tunnelling from amplification

Tunnelling shows many outbound queries carrying long or encoded labels from one internal host. Amplification shows spoofed inbound queries for large record types. The mitigations differ: tunnelling is addressed at the resolver, amplification by response rate limiting at the edge.
