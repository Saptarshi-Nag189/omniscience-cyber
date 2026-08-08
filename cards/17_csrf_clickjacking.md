# CSRF & Clickjacking (UI Redressing)

*Keywords: CSRF, XSRF, cross site request forgery, state changing request forged, no CSRF token, SameSite cookie, clickjacking, UI redressing, iframe overlay, X-Frame-Options, frame-ancestors, password reset CSRF, forge request, anti-CSRF token bypass.*

## CSRF — forcing a victim's authenticated action

CSRF makes a logged-in victim's browser send a state-changing request they didn't intend, because the browser auto-attaches their session cookie. Test any state-changing endpoint (change email/password, transfer, create/delete account, modify a data record): (1) Remove the anti-CSRF token entirely — does it still succeed? (2) Use a different user's valid token — is the token bound to the session or globally valid? (3) Change the method (POST→GET) — is a GET accepted for a state change? (4) Empty/predictable token accepted? (5) Is the token only checked when present (send the request without the header)? (6) Are cookies `SameSite=None`/absent (cross-site send allowed)? Build a minimal auto-submitting HTML form PoC that fires the request from an attacker origin; prove it executes as the victim using a TEST account — do not target real users. **Password-reset / email-change CSRF is the money variant**: force the victim's email to one you control → then reset → account takeover.

## Detecting real CSRF vs protected

A finding requires: the endpoint changes state, relies on the ambient session cookie, and has no effective anti-CSRF defense. Modern defenses that make it NOT a bug: a per-request/per-session unpredictable token that's validated server-side, `SameSite=Lax/Strict` cookies (blocks most cross-site sends), or a required custom header on a JSON API (a cross-site form can't set custom headers, and a non-simple content type triggers preflight). If a JSON endpoint also accepts `application/x-www-form-urlencoded`, test switching content type to bypass the header requirement. Report the specific missing control, and demonstrate the forged action end-to-end.

## Clickjacking / UI redressing

Clickjacking frames the target site invisibly and tricks the victim into clicking a sensitive control (confirm-delete, approve, change-setting) they can't see. Test: can the page be framed? — check for a missing `X-Frame-Options: DENY/SAMEORIGIN` header AND missing CSP `frame-ancestors`. If both are absent, build a PoC: an attacker page with the target in a low-opacity `<iframe>` positioned so a decoy button overlaps the sensitive action; a click lands on the target. Impact depends on what a single framed click can do — a one-click account/setting change or a destructive sensitive action is the strong case. `client_audit.py` already flags missing X-Frame-Options/frame-ancestors.

## CSRF / clickjacking CVSS and remediation

CSRF on a sensitive action (e.g. email change → ATO): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` ≈ 8 High (UI:R because the victim must visit the attacker page); lower for a less-impactful action. Clickjacking on a one-click sensitive control: `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` ≈ 4–6 Medium, higher if the framed action is destructive/ATO. Root causes: state changes authorized by an ambient cookie with no unpredictable per-request token (CSRF); page framable with no frame-busting headers (clickjacking). Remediation: anti-CSRF tokens bound to the session (or `SameSite=Lax/Strict` + a required custom header on JSON APIs); re-auth for high-value actions; set `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` (or an explicit allowlist).
