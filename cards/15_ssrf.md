# Server-Side Request Forgery (SSRF)

*Keywords: SSRF, server side request forgery, fetch internal URL, avatar URL fetch, webhook, cloud metadata, 169.254.169.254, internal service access, blind SSRF, allowlist bypass, url parameter fetches, import from URL, PDF from URL, localhost 127.0.0.1, gopher file protocol.*

## What SSRF is and where to find it

SSRF is making the server issue requests of the attacker's choosing — to internal services, the cloud metadata endpoint, or the loopback interface — by controlling a URL the app fetches. Look anywhere the server fetches a user-supplied URL/host: "import from URL", avatar/logo/image-by-URL, webhooks, PDF/screenshot generators, link previews, XML/SVG parsers (external entities), document converters, health-check/proxy features, and any param that looks like `url=`, `uri=`, `dest=`, `path=`, `feed=`, `callback=`. In a target application, an "import record from URL" or a document-fetch feature is the prime target. SSRF lets an external user pivot the trusted server into the internal network they can't reach directly.

## SSRF detection and high-impact targets (impact-limited)

Detect by pointing the fetch at a target you control or an internal address and observing behavior. Safe, impact-limited probes: (1) **Loopback / internal** — `http://127.0.0.1:<port>/`, `http://localhost/`, internal hostnames; a different response/timing than an external URL proves the server reached it. (2) **Cloud metadata** — `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP); returning instance data / credentials is Critical — read ONE non-secret field to prove reach, do not harvest keys. (3) **Blind SSRF** — if no response is reflected, confirm via out-of-band interaction with an in-scope collaborator/listener you control, or via timing. Do NOT scan the whole internal range (noisy, DoS-like) — prove reachability to one internal endpoint. Alternate schemes to test if HTTP is filtered: `file://`, `gopher://`, `dict://`, `ftp://`.

## SSRF filter/allowlist bypasses

Weak SSRF defenses check the URL string, not the final resolved destination — bypass by: (1) **Alternate IP encodings** — `http://2130706433/` (decimal 127.0.0.1), `http://0x7f000001/`, `http://127.1/`, `http://[::1]/`, `http://0/`. (2) **DNS rebinding / attacker DNS** — a hostname you control that resolves to an internal IP (TOCTOU between check and fetch). (3) **Open redirect chain** — point at an allowlisted host that 302-redirects to an internal target (disable redirect-following is the fix; test if it follows). (4) **Credentials/format tricks** — `http://expected-host@169.254.169.254/`, `http://169.254.169.254#expected-host`. (5) **Uncommon domains** — `169.254.169.254.nip.io`. If a payload is blocked one way but the fetch succeeds another, the allowlist is incomplete — report the reachable internal target.

## SSRF CVSS and remediation

SSRF reaching cloud metadata / internal admin services (credential or sensitive-data exposure): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` ≈ 8–9 (scope change because it crosses into the internal trust boundary); full internal RCE via a reachable service → Critical. Blind SSRF with limited reach: Medium. Root cause: the server fetches a user-controlled URL without validating the *resolved* destination against an allowlist, and follows redirects. Remediation: allowlist by resolved IP (not the URL string), block private/link-local/loopback ranges and the metadata IP, disable unneeded URL schemes and redirect-following, enforce at the network layer (egress firewall / no metadata access), and require the fetch to a small set of known internal endpoints only.
