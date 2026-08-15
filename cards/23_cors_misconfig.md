# CORS Misconfiguration & Cross-Origin Data Theft

*Keywords: CORS, cross-origin resource sharing, Access-Control-Allow-Origin, ACAO reflection, Allow-Credentials true, null origin, wildcard CORS, origin reflection, preflight, cross-origin API read, withCredentials, subdomain trust, prod API CORS.*

## What a CORS misconfiguration is and where it bites

CORS controls which web origins a browser will let read a cross-origin response. A misconfiguration lets an attacker's site issue authenticated requests to the target API *and read the responses* using the victim's cookies — turning any logged-in victim who visits a malicious page into a data-leak vector. The dangerous combination is `Access-Control-Allow-Origin` reflecting/allowing an attacker origin **together with** `Access-Control-Allow-Credentials: true`. Test every API that serves sensitive data to a browser with cookie/session auth: account/profile APIs, admin APIs, anything under `/api/`, and internal tools. This is a *configuration* bug — the fix is a header, but the impact is full authenticated read.

## CORS detection — origin reflection and dangerous values

Send the request with a crafted `Origin` header and inspect the response's `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC):
- **Arbitrary origin reflection** — `Origin: https://evil.example` → ACAO echoes `https://evil.example` and ACAC is `true` = exploitable, any site can read.
- **`null` origin trusted** — `Origin: null` → ACAO `null` + ACAC `true`; reachable from a sandboxed iframe/`data:` document = exploitable.
- **Weak regex / suffix match** — `Origin: https://evil-target.com` or `https://target.com.evil.com` reflected = the allowlist is a substring check.
- **Trusted subdomain + subdomain XSS/takeover** — if only `*.target.com` is trusted, an XSS or a subdomain takeover on any subdomain becomes cross-origin data theft.
Note: ACAO `*` with `ACAC: true` is invalid and browsers reject it — wildcard is only exploitable for *unauthenticated* data. Prove impact by fetching the victim-scoped endpoint from a controlled in-scope origin and showing the response is readable — read **one** record, don't harvest.

## CORS PoC (impact-limited, in-scope)

A minimal proof from a page on an origin you control (or a documented request that would succeed): 
```html
<script>
fetch('https://<in-scope-api>/api/me', {credentials:'include'})
  .then(r=>r.text()).then(d=>/* exfil ONE field to your in-scope listener */);
</script>
```
Host it on your in-scope collaborator, load it as a logged-in test user, and show the API's authenticated JSON is readable cross-origin. Keep it to a single benign field of a **test account** — the point is to demonstrate the browser allowed a credentialed cross-origin read, not to scrape real users. Pair with a screenshot of the ACAO/ACAC response headers for a clean report.

## CORS CVSS and remediation

Credentialed cross-origin read of sensitive authenticated data (reflected origin + ACAC true): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` ≈ 6.5 (UI:R because the victim must visit the attacker page); if it also enables state-changing writes, add integrity impact. Root cause: ACAO derived from the request `Origin` (reflection) or a loose allowlist, combined with `Allow-Credentials: true`. Remediation: never reflect `Origin` — match it against a strict, exact allowlist of trusted origins; only send `Access-Control-Allow-Credentials: true` for those exact origins; never trust `null`; avoid `*` for authenticated endpoints; validate the full origin (scheme+host+port), not a substring/regex; and remember CORS is not a substitute for CSRF protection on state-changing requests.
