# Testing Hardened Targets — Assume Real Defenses

*Keywords: WAF bypass, payload blocked, defense in depth, secure target, no vulnerabilities found, target looks secure, rate limiting, well defended app, where to look when basics are secure, second order, edge cases, API versioning gap, seams, hardened, nothing works.*

## Assume the target is well-defended (mindset)

This app was built by a capable team and likely has real defenses: a WAF, server-side authorization, input validation, rate limiting, TLS pinning, parameterized queries, CSRF tokens, short-lived signed tokens. Do NOT conclude "secure" from a blocked naive payload — that only means the obvious path is closed. Distinct, high-value bugs live in the SEAMS: inconsistent enforcement across endpoints, a new/less-guarded API version, a code path the main framework doesn't cover, the mobile API vs the web API, edge states. Be systematic, not lucky: map every endpoint and test each against the full authz/injection matrix, because one forgotten handler out of hundreds is the finding. Rigor beats payload-spraying against a hardened target.

## Where bugs hide when the basics are secure

When the front door is locked, test: (1) Inconsistency — authz enforced on `/api/v2/record` but not `/api/v1/record`, or on GET but not the newer PATCH; the mobile endpoint but not an internal/admin one. (2) Second-order — input that's sanitized on entry but unsafe when later used (stored XSS/SQLi in a report/export/admin view). (3) Logic over payload — race conditions, state-machine skips, mass assignment, IDOR on UUIDs leaked elsewhere — WAFs don't catch these because there's no malicious string. (4) Trust boundaries — the app trusts an internal header (`X-Forwarded-For`, `X-User-Id`, `X-Internal`), a JWT claim, or the mobile client's assertions. (5) Newer/edge features — recently added endpoints, file upload/convert, webhooks, import — less battle-tested.

## Defeating specific defenses (test methodology, not evasion for its own sake)

Against real controls, test whether they're complete, not just present: (1) WAF — try alternate encodings/case/whitespace, JSON vs form body, HTTP parameter pollution, chunked/multipart; if a payload is blocked one way but the endpoint is reachable another, the WAF is a bypassable band-aid over a real bug (report the underlying bug). (2) Rate limiting — check if it's per-IP (rotate not needed; note gap), per-account, or absent on a specific sensitive endpoint (OTP/reset) — a single unthrottled sensitive endpoint is the finding. Stay within no-DoS rules: probe the LIMIT, don't flood. (3) SSL pinning (mobile) — Frida/objection unpin on a test device to reach the API; the pinning isn't the bug, what you find behind it is. (4) CSRF tokens — test if they're actually validated, bound to the session, and required on state-changing requests.

## Serious-tester checklist (don't self-limit)

Treat a "no result" as "not yet proven," not "safe." For each candidate: did I test every identity (anon/userA/userB/admin), every HTTP method, every API version, both web and mobile clients, and the second-order path? Did I try the request the UI never sends (extra fields, other ids)? Is the control enforced server-side or just client-side/UI-hidden? Have I distinguished "the WAF blocked my string" from "the endpoint is safe"? Confirm every finding is reproducible and server-side before writing it up. Against a hardened target, the winning findings come from exhaustive coverage and logic bugs — not from the first payload that pops.
