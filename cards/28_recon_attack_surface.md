# Recon & Attack-Surface Mapping (Scope-Bounded)

*Keywords: recon, reconnaissance, attack surface, subdomain enumeration, subfinder amass, crt.sh, certificate transparency, httpx, content discovery, wayback, gau, katana, asn, dns, passive recon, scope, in-scope enumeration, endpoint discovery, tech fingerprint.*

## Recon that stays inside authorized scope

Good recon finds the endpoints where the real bugs live — but every technique here must stay within the engagement's authorized scope. **Confirm scope first**: which apex domains, subdomains, IP ranges/ASNs, and wildcard rules are in scope, and whether third-party/SaaS assets are excluded. Split recon into **passive** (no packets to the target — safe, quiet) and **active** (touches the target — throttle, in-scope only). Prefer passive first to build the map, then confirm live with light active probes. Never enumerate or probe hosts you can't tie back to the authorized scope; an in-scope-only allowlist is the guardrail for the whole phase.

## Passive recon (no direct target traffic)

Build the surface without touching the target: **Subdomains from Certificate Transparency** — `crt.sh` (`%.target.com`), `subfinder`/`amass enum -passive` (aggregate CT + passive DNS sources). **Historical URLs** — `gau`, `waybackurls`, `github-endpoints` surface old endpoints, parameters, and forgotten APIs. **Public exposure** — Shodan/Censys/FOFA for the target's known IPs/ASN (services, banners, exposed panels); GitHub/GitLab dorking for leaked keys, internal hostnames, and config in the org's public repos; Google dorks (`site:target.com ext:` , `inurl:`). All of this generates **candidate assets** — validate each against scope before you send it a single request.

## Active recon (throttled, in-scope only)

Once you have in-scope candidates: **resolve + probe live hosts** — `httpx` (titles, status, tech, TLS SANs) over the subdomain list; **light port/service check** — `nmap -sV -T2 <in-scope-host>` (no `-T5`, no broad internet ranges, no aggressive scripts against fragile prod). **Content & endpoint discovery** — `ffuf`/`feroxbuster` for dirs/files (`-rate` limited, e.g. `ffuf -u https://host/FUZZ -w seclists/.../common.txt -rate 30`), `katana -jc` for JS-aware crawling that extracts SPA/API routes and parameters, and pull `robots.txt`/`sitemap.xml`/JS source-map endpoints. **Fingerprint the stack** (`whatweb`, response headers, framework tells) to pick the right bug-class cards. Throttle everything, run active recon only against confirmed in-scope hosts, and stop scans that look load-bearing on production — recon should be quiet, not a stress test.

## Recon output, scoring, and handoff

Recon itself is rarely a "finding," but it produces the inputs everything else scores against, and some results *are* reportable: an exposed admin/staging panel, a leaked secret in a public repo, a dangling DNS record (see the takeover card), directory listing, or a `.git`/`.env` exposure. Score those on their own impact (e.g. exposed `.git` enabling source disclosure ≈ `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5). Keep a clean asset inventory (host → tech → interesting endpoints → which bug-class card to try) so testing is systematic and de-duplicated. Feed discovered object/ID endpoints into IDOR/authz testing, discovered parameters into injection testing, and discovered subdomains into the takeover check — recon is the map, the bug-class cards are the routes.
