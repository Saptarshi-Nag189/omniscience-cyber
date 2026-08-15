# Race Conditions — TOCTOU & Limit-Overrun Bugs

*Keywords: race condition, TOCTOU, time of check time of use, concurrent requests, double spend, limit overrun, coupon reuse, single packet attack, parallel requests, atomicity, idempotency, gift card, balance race, turbo intruder, multi-thread request.*

## What a race condition is and where it pays off

A race condition is when two requests hit a non-atomic check-then-act sequence at the same time, so both pass a check that should only pass once. In web apps this shows up as **limit overruns**: apply a one-time coupon N times, withdraw/transfer more than the balance (double-spend), redeem a gift card twice, bypass a "one vote / one signup / one review" rule, over-draw a rate/quota limit, or use a single-use token/OTP more than once. Look for any action guarded by "check a value, then decrement/consume it" that isn't wrapped in a database transaction or lock: wallet/balance operations, promo/coupon redemption, invite/referral credits, MFA/OTP consumption, and "claim once" mechanics.

## Race-condition detection — controlled, impact-limited

Prove it by firing a small burst of identical requests as simultaneously as possible and checking whether the guarded action succeeded more times than allowed. Tooling: **Burp Repeater "Send group in parallel"** (single-packet attack, best for HTTP/2 — minimizes network jitter), or **Turbo Intruder** with a gate to release, e.g. ~20–50 concurrent copies. Keep the burst **small** (tens, not thousands) — you're demonstrating non-atomicity, not stress-testing; a large flood would be DoS-like and out of rules of engagement. Use a **test account** with a test coupon/balance so no real money or user data is touched. Clear proof = "applied the single-use $10 coupon 6 times → balance reflects 6×" with the request group and the resulting state as evidence. If the endpoint is idempotent or transactional, the burst yields exactly one success — that's a clean negative.

## Race-condition variants and tips

**Multi-endpoint (TOCTOU across requests)** — race a "validate" call against a separate "commit" call (e.g. confirm a discount then change the cart). **State-machine skips** — race two steps of a flow so a later step runs before an earlier guard commits. **Session/registration races** — parallel signups with the same email/username to create duplicates that break uniqueness assumptions. Maximize the odds by removing variables: reuse one valid session, keep payloads byte-identical, prefer HTTP/2 single-packet, and warm the connection first. Confirm reproducibility (run the small burst 2–3 times) so the finding is solid, then stop.

## Race-condition CVSS and remediation

A balance/coupon race causing direct financial impact (double-spend, unlimited discount): `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` ≈ 5.9 (AC:H reflects timing sensitivity) — argue higher if funds move at scale or auth is bypassed; a race defeating a security limit (OTP reuse, brute-force gate) can reach High. Root cause: a check and the state change it protects are not atomic, so concurrent requests interleave. Remediation: make the guarded operation atomic — database transactions with proper isolation, `SELECT ... FOR UPDATE` / row locks, atomic conditional updates (`UPDATE ... WHERE balance >= amount`), unique constraints for one-time actions, and idempotency keys so retries/duplicates collapse to a single effect; avoid read-modify-write in application code without a lock.
