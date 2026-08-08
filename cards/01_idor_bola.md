# IDOR / BOLA — Broken Object-Level Authorization

*Keywords: IDOR, BOLA, insecure direct object reference, broken object level authorization, access another user's record, change the id in the URL, /api/record/{id}, unauthorized data access, object ownership check, enumerate ids, horizontal access, view someone else's data, citizen record leak.*

## What IDOR/BOLA is and why it is the top-value bug

IDOR (Insecure Direct Object Reference), also called BOLA (Broken Object-Level Authorization, OWASP API #1), occurs when an endpoint exposes an object by an identifier the client supplies (e.g. `/api/record/1234`) and the server returns or mutates that object WITHOUT verifying the authenticated caller owns it or has a role permitting it. It is the single highest-yield class in most bounties because it is common, easy to prove, and often Critical when the object holds PII. In a target application context the objects are citizen records, household data, government-ID fields — exposure of another person's record is High-to-Critical impact.

## How to detect IDOR: the differential test

The rigorous method is a DIFFERENTIAL replay across identities, which is exactly what `authz_matrix.py` automates. Procedure: (1) as user A, capture a request to an object A owns, note the id. (2) Re-send the identical request as user B (a different, equal-privilege account). (3) If B receives A's object (HTTP 200 with A's data), it is a horizontal IDOR. (4) Re-send as anonymous — if anon is denied but B is allowed, that confirms authz exists but is not object-scoped (true IDOR, not just missing auth). The anon-denied gate is the discriminator that separates real IDOR from an endpoint that is simply public.

## IDOR test surfaces (where the ids live)

Look for client-controlled object references in: URL path segments (`/user/1001/profile`), query params (`?id=`, `?account=`, `?doc=`), request body fields (JSON `"userId"`, `"recordId"`), custom headers (`X-User-Id`), and indirect refs (a filename, a UUID, a base64 token that decodes to an id). Sequential integer ids enable enumeration; UUIDs still IDOR if leaked elsewhere (in listings, referrer, mobile app). Test state-changing verbs too — POST/PUT/PATCH/DELETE IDOR (editing/deleting another user's record) is often higher severity than a read.

## IDOR CVSS and remediation (paste-ready)

Read of another user's PII, authenticated low-priv attacker: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5 Medium; raise C:H→ and add I:H for write/delete IDOR → `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 High. If the object is mass-enumerable (sequential ids, no rate limit) the effective impact is a full-database read — argue Critical in the write-up. Root cause: authorization decided by presence of a valid session, not by ownership of the requested object. Remediation: enforce server-side object-level authorization on EVERY request — verify the authenticated principal owns or has a role for the specific object id before returning/mutating it; never trust the client-supplied id alone.
