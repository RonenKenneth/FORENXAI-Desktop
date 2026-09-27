# Credential attack — response

> **PLACEHOLDER.** Written to exercise the retrieval and citation-verification
> path, not sourced from any standard. Replace the body of each section with
> the relevant text of NIST SP 800-61r3 and your own runbook before this is
> used on real traffic. Keep the heading structure intact: the retrieval and
> quote-verification steps depend on it.

## 4.1 Detection and analysis

Record the targeted account names, the source addresses, the service and the number of failed authentications per account. Establish whether any authentication succeeded during the window. A success after repeated failures changes this from an attempted compromise to a confirmed one and changes the response.

## 4.2 Containment

Force a password reset on any account that authenticated successfully during the attempt window, and lock any account still under active attempt. Apply per-source rate limiting on the authentication endpoint. Do not block on the basis of a single detection: a misconfigured client retrying a stale credential produces the same pattern as an attack.

## 4.3 Eradication and recovery

Require a password change for every targeted account before re-enabling it. Restore normal lockout thresholds once the source traffic has stopped for a sustained period. Record the configuration change and its reversal in the incident log.

## 4.4 Distinguishing spraying from classic brute force

Classic brute force shows many attempts against one account. Password spraying shows few attempts against many accounts and is usually tuned to stay under the lockout threshold. Spraying is the one a per-account threshold does not see, so count attempts per source as well as per account.
