# Business Logic & Unauthorized Account/Record CRUD

*Keywords: business logic flaw, logic bug, race condition, mass assignment, unauthorized account creation, modify another user, delete account, record tampering, integrity attack, skip workflow step, state machine abuse, replay action, edit approved record, extra fields in request.*

## Business-logic flaws (the non-payload bugs)

Business-logic flaws are abuses of legitimate features in an unintended order or state — no injection payload, so scanners miss them and they are rarely duplicates. Test patterns: (1) Skip a step — go straight to a post-approval/post-payment endpoint. (2) Replay — resubmit a one-time action (voucher, OTP, vote, submission) many times. (3) Negative/overflow values — quantities, IDs, prices as negative or huge. (4) State machine abuse — reopen a closed record, edit an approved/locked data entry, un-finalize a submitted form. (5) Race conditions — fire the same request concurrently to double-spend or bypass a one-per-user check (keep it to a few requests, never a flood — no DoS). Frame the impact as data integrity or authorization violation.

## Unauthorized account CRUD (create / modify / delete)

High-impact programs explicitly reward unauthorized account create/modify/delete. Test: (1) Can a normal user hit admin user-management endpoints (`POST /api/users`, `PUT /api/users/{id}`, `DELETE`)? That's function-level authz failure. (2) Mass assignment — include extra fields the UI never sends (`"role":"admin"`, `"verified":true`, `"balance":0`) in a profile-update request; if the server binds them, you self-escalate. (3) Account modify via IDOR — change another user's email/phone (then trigger password reset = takeover). (4) Delete/deactivate another user's account by id. Each is High-to-Critical: it violates integrity of the user dataset. PoC by creating/altering a TEST account only — never a real user.

## Record tamper & integrity attacks

record data integrity is high-value: unauthorized modification or deletion of records. Test whether a low-priv or peer user can (1) edit fields they should only read (household size, address, national-ID linkage, status flags), (2) delete or soft-delete another user's records, (3) alter audit/approval fields (`approvedBy`, `status`, timestamps) directly via the API bypassing workflow, (4) tamper with export/report generation to inject or hide records. Confirm the mutation persisted server-side (re-read as the owner). Integrity impact on official user records is a strong severity argument (I:H), often High even without confidentiality loss.

## Business-logic CVSS and remediation

Unauthorized record modify/delete on user records: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = 5.3–6.5; if it also exposes data add C:H → `C:H/I:H` = 8.1 High; account create/delete abuse affecting many principals → argue High/Critical via broad impact. Mass-assignment self-escalation to admin = 8.1+ High. Root cause: server trusts client for authorization/state transitions and binds client-supplied fields without an allowlist; no server-side workflow/ownership enforcement. Remediation: enforce state machines and ownership server-side, bind only an explicit allowlist of writable fields per role, make one-time actions idempotent/locked, and re-validate every privileged mutation against the session principal.
