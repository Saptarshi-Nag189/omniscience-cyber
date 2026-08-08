# Cross-Site Scripting (XSS) & Client-Side Injection

*Keywords: XSS, cross site scripting, reflected XSS, stored XSS, DOM XSS, JavaScript injection, script injection, alert(1), payload reflected, HTML injection, CSP bypass, dalfox, innerHTML, document.write, sink, source, client-side injection.*

## XSS types and where to test

XSS is attacker-controlled input executing as script in a victim's browser. Three types: (1) **Reflected** — input echoed straight back in the response (search boxes, error messages, query params reflected in HTML). (2) **Stored** — input saved then rendered to other users (profile fields, comments, data record fields shown in an admin/report view — high impact, hits other users incl. admins). (3) **DOM-based** — client-side JS writes untrusted data into a sink (`innerHTML`, `document.write`, `eval`, `location`) with no server round-trip. Test every input that ends up in a page: params, form fields, headers reflected in HTML (Referer/User-Agent), filenames, JSON rendered into the DOM. In a target application, stored XSS in a field a privileged user later views is the money variant.

## Detecting XSS safely (impact-limited PoC)

Detect without disruptive payloads. (1) Inject a unique probe like `xss7331` and find where it reflects — note the context (HTML body, attribute, `<script>`, URL, JS string). (2) Break the context minimally: in HTML body `<u>xss7331</u>` (renders = injectable), in an attribute `"><u>x</u>`, in JS `';alert(document.domain)//`. (3) Confirm execution with a benign, self-contained PoC: `alert(document.domain)` proves it in YOUR browser only — do NOT hook other users, steal real cookies, or deface. `document.domain` in the alert proves origin without touching data. For stored XSS, use a test account and view it as the intended-victim role to prove cross-user execution. Automate reflected/DOM discovery with `tools/dalfox url --url "https://host/x?q=1" --cookie "SESSION=..."` (throttle with `--delay`).

## Context, CSP, and filter-bypass notes

Match payload to context or it won't fire: HTML body → `<img src=x onerror=alert(document.domain)>`; attribute → close the attr then add a handler; inside `<script>` → break the JS string/expression; inside a URL → `javascript:` scheme (for sinks/redirects). If a WAF/filter blocks `<script>`, that's not "safe" — try event handlers (`onerror`,`onfocus autofocus`), SVG (`<svg onload=…>`), case/encoding variation, or a DOM sink the server-side filter never sees. A **CSP** may block inline script — check the `Content-Security-Policy` header: `unsafe-inline`, overly broad `script-src`, or a bypassable allowlisted host weakens it; report a real reflection even if CSP currently blunts it (defense-in-depth, not a fix). DOM XSS often bypasses server filters entirely — trace source→sink in the JS.

## XSS CVSS and remediation

Reflected XSS (requires victim interaction): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1 Medium (scope-changed because script runs in the victim's origin). **Stored XSS** hitting other users/admins with no interaction beyond viewing: raise to `UI:N` and higher C/I → `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` ≈ 8.x High; stored XSS that steals an admin session = account takeover, argue High/Critical. DOM XSS scores like reflected unless it's stored-then-DOM. Root cause: untrusted input rendered into a page (or a DOM sink) without context-correct output encoding. Remediation: context-aware output encoding (HTML/attribute/JS/URL), a strict CSP (`script-src` no `unsafe-inline`, nonce/hash-based), framework auto-escaping left on, avoid dangerous sinks (`innerHTML`/`eval`) — sanitize with a vetted library (DOMPurify) when HTML is required.
