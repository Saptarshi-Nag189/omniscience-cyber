# Authorization Bypass & Privilege Escalation

*Keywords: privilege escalation, privesc, become admin, user to admin, vertical escalation, horizontal escalation, broken access control, missing authorization, forced browsing, admin endpoint, role tampering, isAdmin, elevate privileges, access admin function, BFLA, broken function level authorization.*

## Vertical privilege escalation (User → Admin)

Vertical escalation is a low-privilege user gaining higher-privilege (admin/super-admin) capability. Test method: enumerate admin-only endpoints (from JS bundles, the mobile APK, the admin UI, or guessing `/admin`, `/api/admin/*`, `/manage`), then send those requests with a NORMAL user's session. If the server executes the privileged action, it relies on the UI hiding the button rather than server-side role checks — a Broken Function-Level Authorization (OWASP API #5). Also test role tampering: flip a `role`, `isAdmin`, `type` field in the request body, JWT claim, or a hidden form field, and replay. `authz_matrix.py` classifies this as VERTICAL_ESCALATION when a normal identity succeeds on an endpoint anon is denied and that admin/owner alone should reach.

## Horizontal privilege escalation

Horizontal escalation is accessing a same-level peer's resources — mechanically identical to IDOR but framed as "same role, other tenant/user." In a target application: user A viewing user B's assigned households, or citizen A editing citizen B's record. Prove it with the differential replay (user A object accessed by user B). Distinguish from vertical by noting both principals hold the same role; the flaw is object-scoping, not role-scoping. Severity tracks the data: peer PII read = High; peer record modify/delete = High-to-Critical.

## Authorization bypass techniques (forced browsing & flaw patterns)

Beyond replay, test these authz bypass patterns: (1) Forced browsing — request a resource you were never linked to. (2) Parameter pollution — duplicate params `?id=mine&id=victim`. (3) HTTP method swap — if GET is blocked, try POST/PUT/HEAD/OPTIONS. (4) Path/case tricks — `/Admin`, `/admin/`, `/admin/.`, `/%2e/admin`, added `..;/`. (5) Missing-object-check on nested routes — `/api/org/1/user/999` where org is checked but user is not. (6) Referer/Origin-based checks that are trivially spoofable. (7) Front-end-only guards — the endpoint has no server check at all. Confirm anon is denied to prove the control exists but is misapplied.

## Authz CVSS and remediation

Vertical escalation to admin actions: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 High; if it yields full account/system control argue `C:H/I:H/A:H` = 8.8 High or Critical with scope change. Missing function-level authz reachable by ANY authenticated user is High. Root cause: authorization enforced at the presentation layer or by role-claims the client can influence, not re-verified server-side per action against the trusted session principal. Remediation: deny-by-default server-side authorization; derive the principal's role and object ownership from the server session/token signature, never from client-supplied fields; check on every function and every object.
