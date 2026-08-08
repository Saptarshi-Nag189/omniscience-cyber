# HTTP Verb Tampering & Systematic Authz Testing

*Keywords: HTTP verb tampering, method tampering, VBAAC bypass, verb based access control, GET vs POST authz, HEAD bypass, PUT PATCH DELETE not protected, method override, X-HTTP-Method-Override, authorization matrix, test every method, authz regression, tenant isolation.*

## HTTP verb / method tampering

Many apps enforce authorization per-URL but not per-method — a classic "verb-based access control" (VBAAC) flaw. If `POST /admin/deleteUser` is blocked for a normal user, test the SAME path with a DIFFERENT method: `GET`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`. Frameworks that map a security constraint to specific verbs (e.g. a Java `<http-method>GET</http-method>` constraint) leave the un-listed verbs unprotected — so `HEAD /admin/...` may execute the action while bypassing the GET-only check, and an arbitrary method sometimes falls through to a permissive default. Also test **method override** headers/params the server may honor: `X-HTTP-Method-Override: PUT`, `X-Method-Override`, `_method=DELETE` in the body — these let you smuggle a privileged verb through a filter that only inspects the real method. A state-changing action reachable via an unguarded verb is a direct broken-access-control finding.

## Test EVERY endpoint across the full matrix

The reliable way to find authz bugs on a hardened target is exhaustive matrix coverage, not spot checks. For each sensitive endpoint, vary FOUR axes: (1) **Identity** — anon, userA, userB (peer), admin. (2) **Method** — GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS. (3) **Object** — your own id vs another user's/tenant's id (IDOR/tenant isolation). (4) **API version / client** — `/v1` vs `/v2`, web vs mobile endpoint. A single cell where a request that SHOULD be denied returns success is the bug. `authz_matrix.py` automates the identity×object axes with the anon-denied gate; add method and version variation manually for the endpoints that matter. Keep a machine-readable matrix (which role may do which method on which object) so nothing is skipped — this is exactly how "Day 2" regressions (a new endpoint shipped without an authz check) get caught.

## Tenant isolation & horizontal boundary

Beyond user-vs-user, test **tenant/org isolation**: in `/api/org/{orgId}/resource/{id}`, is `orgId` enforced, or can userA in org1 read org2 by changing `orgId` (or by keeping their own `orgId` but requesting another org's `resourceId`)? Nested resources often check the outer id but not the inner one. For a target application think tenant-region / household-cluster boundaries: can a user assigned to region A read/modify region B's records? Prove it with the differential replay (peer identity, other tenant's object, expect-deny→got-success). Tenant-crossing reads of citizen data are High-to-Critical.

## Verb-tampering / matrix CVSS and remediation

Verb tampering to a privileged state-changing action (e.g. delete/modify as a normal user): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 High; unauthenticated → `PR:N` higher. Tenant-isolation break exposing another org's data: High. Root cause: authorization enforced per-URL-and-specific-verb (or at a gateway that doesn't see overrides) instead of per-action on the resolved principal+object+operation. Remediation: enforce authorization on the actual operation regardless of HTTP method; deny unlisted methods by default (return 405, don't fall through); ignore client method-override headers unless explicitly required; check object AND tenant ownership on every request from the trusted session, not from client-supplied ids.
