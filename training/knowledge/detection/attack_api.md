# API abuse — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Abuse of REST, GraphQL or SOAP endpoints: mass assignment, injection, XXE and authorisation bypass against a machine-facing interface.

## 1.2 How it appears in flow records

Regular, machine-timed request intervals against a small set of destination ports, with consistent forward packet sizes. `Dst Port` is usually the strongest single feature, which is also the reason to be careful with it.

## 1.3 Classes it is confused with

WebBased, because both are application-layer attacks over HTTP and the flow records rarely separate them. Exploitation, where the payload targets the server rather than the application.

## 1.4 Common false positives

API test suites, contract tests and synthetic monitoring generate the same regular machine-timed pattern against the same endpoints.
