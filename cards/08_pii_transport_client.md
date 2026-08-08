# PII Exposure, Transport Security & Client-Side Leaks

*Keywords: PII exposure, sensitive data leak,  exposed, excessive data in API response, over-exposure, BOPLA, broken object property level authorization, cleartext HTTP, token in URL, weak CORS, secrets in JavaScript, source maps, HSTS, data in transit, information disclosure.*

## PII exposure and excessive data return

PII exposure is high-value (names, addresses,  phone, household composition). Test for over-exposure: (1) API returns MORE fields than the UI shows — inspect raw JSON for hidden `national_id`, `dob`, `ssn`, `phone`, internal ids, password hashes. This is Broken Object Property-Level Authorization (OWASP API #3). (2) List/search endpoints that page through all records (`?limit=1000`, `?page=`) exposing bulk PII. (3) Debug/verbose modes leaking stack traces, SQL, internal paths. (4) Predictable export URLs (`/export/report.csv`). (5) PII in error messages, autocomplete, or cached responses. Prove with a single record's excess fields — do not bulk-harvest real PII (rules: PoC-limited, test data only).

## Transport security & sensitive data in transit

Test transport: (1) HTTP (not HTTPS) anywhere, or mixed content. (2) Sensitive data in URL query strings (tokens, ids, PII) — logged by servers/proxies, leak via Referer. (3) Missing HSTS. (4) Weak TLS config (only relevant if in scope; do not scan out-of-scope hosts). (5) Tokens/secrets in response headers or `Set-Cookie` without `Secure`. For mobile: cleartext HTTP traffic (`usesCleartextTraffic`), no certificate pinning (Burp/mitmproxy intercepts the API), TLS errors ignored in code. Capturing credentials or PII over cleartext, or trivially MITM-ing the mobile API, is a solid Medium-to-High finding.

## Client-side leaks: JS, CORS, secrets in front-end

Front-end recon (feeds authz_matrix + recon.py): (1) Secrets in JS bundles — grep for `api_key`, `apikey`, `token`, `AKIA`, internal hostnames, admin endpoints referenced but UI-hidden. `katana -jc` crawls JS to surface these. (2) Source maps (`.js.map`) exposing original source. (3) Weak CORS — `Access-Control-Allow-Origin: *` with credentials, or origin reflection (`ACAO: <your-evil-origin>` + `ACAC: true`) lets a malicious site read authenticated responses. Test by sending `Origin: https://attacker.example` and checking the reflected ACAO. (4) `postMessage` handlers, DOM sinks, localStorage holding tokens (XSS-stealable). (5) Verbose comments/TODO/credentials in HTML/JS.

## PII/transport/client CVSS and remediation

Excess-PII API exposure (/DOB returned to any authenticated user): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5; unauthenticated bulk PII → `PR:N` = 7.5 High. Credential-reflecting CORS misconfig: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N` ≈ 7–8. Cleartext PII/token in URL or HTTP: Medium (5.x), higher if it enables ATO. Root causes: no object-property-level authz (serializer returns all columns), secrets shipped to the client, permissive CORS/transport defaults. Remediation: response DTOs that expose only per-role-permitted fields, no secrets in client code, strict CORS allowlist (never reflect origin with credentials), HTTPS+HSTS everywhere, keep tokens out of URLs.
