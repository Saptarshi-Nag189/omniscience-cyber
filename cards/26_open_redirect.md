# Open Redirect

*Keywords: open redirect, unvalidated redirect, ?next= ?url= ?return= ?redirect=, url redirection, phishing redirect, oauth redirect chaining, // bypass, whitelist bypass, location header, meta refresh, javascript redirect.*

## What open redirect is and why it matters

An open redirect is a parameter that sends the browser to any attacker-supplied URL. On its own it's usually **Low** severity (phishing: a link on the trusted domain that bounces to a lookalike). Its real value in a pentest is as a **chaining primitive**: it steals OAuth `code`/`token` (see the OAuth card), bypasses SSRF/redirect allowlists, and turns a "trusted domain only" CORS/redirect check into a bypass. Look for redirect-after-login/logout, `?next=`, `?url=`, `?return=`, `?redirect=`, `?dest=`, `?continue=`, `?returnUrl=`, `?callback=`, and any 3xx `Location` derived from input, plus client-side `window.location = param` and `<meta http-equiv=refresh>`.

## Detection and allowlist bypasses

Set the parameter to an external host you control and see if you land there: `?next=https://evil.example`. If naive validation blocks obvious externals, bypass: **scheme-relative** `//evil.example` and `/\evil.example` (browsers treat `\` as `/`); **whitelist-substring** `https://trusted.com.evil.example` or `https://evil.example/trusted.com` or `https://evil.example#trusted.com` / `?x=trusted.com`; **credential trick** `https://trusted.com@evil.example`; **backslash/encoding** `https:/\evil.example`, `%2f%2fevil.example`, double-encoding; **path append** `https://trusted.com/redirect?u=//evil.example` chained; **`javascript:`/`data:`** if the sink is client-side (that's also XSS). Proof = the browser navigates to your host; keep the destination a benign in-scope page. Grab the request + resulting `Location`/navigation for the report.

## Open-redirect CVSS and remediation

Standalone open redirect (phishing aid): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` ≈ 4.7 (often reported Low/Medium); when chained to steal an OAuth token or bypass an SSRF/CORS allowlist, score the **resulting** impact (frequently High/Critical) and describe the chain. Root cause: a redirect target taken from user input without validation. Remediation: don't put URLs in redirect parameters — use server-side mapping (an ID/enum → known internal path); if external redirects are required, allowlist exact hosts and validate the fully parsed URL (scheme + host), reject scheme-relative (`//`, `\`) and userinfo (`@`) forms, and show an interstitial "you are leaving" page for anything off-domain.
