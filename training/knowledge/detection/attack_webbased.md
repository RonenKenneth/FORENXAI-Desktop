# WebBased — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Web application attack: injection, cross-site scripting and path traversal against a browser-facing application.

## 1.2 How it appears in flow records

Irregular request intervals across many distinct paths on ports 80 and 443, with variable forward packet lengths reflecting differing payload sizes.

## 1.3 Classes it is confused with

API, because both are application-layer attacks over HTTP that flow records rarely separate. Exploitation, when the payload targets the server rather than the application.

## 1.4 Common false positives

Web vulnerability scanners, security regression suites, and crawlers that probe unusual paths.
