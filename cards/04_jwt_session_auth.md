# JWT, Session & Authentication Flaws

*Keywords: JWT, JSON web token, alg none, algorithm confusion, weak JWT secret, forge token, account takeover, ATO, session fixation, session hijack, password reset flaw, OTP bypass, MFA bypass, authentication bypass, login bypass, cookie flags, HttpOnly Secure SameSite.*

## JWT attacks (test with jwt_tool)

JSON Web Tokens fail in predictable ways; test with `python tools/jwt_tool/jwt_tool.py <JWT>`. Key checks: (1) alg=none — set header `"alg":"none"`, strip the signature; if accepted, you forge any identity. (2) Algorithm confusion RS256→HS256 — if the server verifies an HS256 token using the RSA public key as the HMAC secret, sign your own token with that public key. (3) Weak HMAC secret — brute the HS256 secret against a wordlist (`jwt_tool -C -d wordlist`); if cracked, forge admin tokens. (4) `kid` injection — path traversal or SQLi in the `kid` header. (5) Missing expiry / no revocation — replay an old token. Forging a token that flips `sub`/`role`/`isAdmin` to admin is a direct account-takeover / vertical-escalation PoC.

## Session management weaknesses

Test the session lifecycle: (1) Predictable/short session ids — analyze entropy. (2) Session not rotated on login — session fixation: set a known id pre-auth, victim logs in, you reuse it. (3) Token in URL — session id in query string leaks via logs/Referer. (4) No server-side invalidation on logout/password-change — old session still works. (5) Long-lived tokens with no idle timeout. (6) Cookie flags missing — no `HttpOnly` (XSS steals it), no `Secure` (sniffable), weak `SameSite` (CSRF). (7) Concurrent sessions never capped. Prove impact by continued access after a state change that should have revoked the session.

## Authentication bypass & account takeover

Account-takeover (ATO) chains to test: (1) Password reset flaws — host-header poisoning to hijack the reset link, guessable/non-expiring tokens, reset-token tied to email you control but applied to victim's account (id in body). (2) OTP/MFA bypass — no rate limit on OTP (brute 000000–999999), OTP returned in the API response, MFA step skippable by going straight to the post-MFA endpoint. (3) Response manipulation — change `"success":false` to `true`, or a 302-to-login that still sets a valid session. (4) Registration flaws — duplicate-email takeover, mass-assignment of `role` at signup. Each yields Critical if it grants another user's or admin's account.

## Auth/JWT CVSS and remediation

Full account takeover (any user): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 8.1–8.6 High; admin ATO or auth bypass granting system control → Critical (9.x). JWT alg=none / weak-secret forgery to admin = Critical. Root causes: trusting client-controlled auth material, missing server-side verification, no token rotation/revocation. Remediation: verify JWT signature with a pinned algorithm and strong secret/keys; short expiry + revocation list; rotate session on privilege change; rate-limit + lock OTP/reset flows; bind reset tokens to the requesting account server-side; set `HttpOnly; Secure; SameSite=Strict` cookies.
