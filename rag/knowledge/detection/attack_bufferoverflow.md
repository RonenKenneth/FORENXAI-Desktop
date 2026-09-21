# BufferOverflow — detection notes

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 1.1 What this class covers

Memory-corruption exploitation against a listening service: oversized or malformed input intended to overwrite adjacent memory.

## 1.2 How it appears in flow records

A small number of flows carrying unusually large forward packets to a service port, often followed by a connection reset or by new outbound activity from the target.

## 1.3 Classes it is confused with

Exploitation. The model confuses these in 8.9% of cases and the response overlaps substantially; the two are flagged as an ambiguous pair and reported together.

## 1.4 Common false positives

Legitimate large uploads, file transfer over a non-standard port, and protocol fuzzing run by an authorised tester.
