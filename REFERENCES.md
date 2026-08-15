# References & Sources

The distilled security cards in `cards/` are original condensations written for fast retrieval,
but the underlying techniques, taxonomies, and severity guidance derive from these public,
authoritative sources. Credit to their authors and maintainers.

## Primary frameworks
- **OWASP Web Security Testing Guide (WSTG)** — https://owasp.org/www-project-web-security-testing-guide/
- **OWASP API Security Top 10 (2023)** — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  (cards cite e.g. "OWASP API #1 BOLA", "#3 BOPLA", "#5 BFLA")
- **OWASP Top 10 (2021)** — https://owasp.org/Top10/
- **OWASP Cheat Sheet Series** — https://cheatsheetseries.owasp.org/
  (Password Storage, Authorization, XSS Prevention, SQLi Prevention, IDOR, Deserialization,
   OS Command Injection, Unvalidated Redirects, Mobile App Security, Access Control)
- **OWASP MASTG / MASVS** (mobile) — https://mas.owasp.org/
- **CWE** — https://cwe.mitre.org/
- **FIRST CVSS v3.1** — https://www.first.org/cvss/v3-1/ · calculator: https://www.first.org/cvss/calculator/3.1
- **PortSwigger Web Security Academy** — https://portswigger.net/web-security
  (labs/technique references for SSTI, deserialization, GraphQL, CORS, OAuth, race conditions,
   request smuggling, and cache attacks)

## Card ↔ topic map
| Card | Topic | Key refs |
|---|---|---|
| 01 | IDOR / BOLA | OWASP API #1, CWE-639 |
| 02 | Authorization / privilege escalation | OWASP API #5 BFLA, CWE-285 |
| 03 | SQL injection | WSTG-INPV-05, CWE-89 |
| 04 | JWT / session / auth bypass | OWASP ASVS, CWE-287/384 |
| 05 | Injection / RCE | WSTG-INPV, CWE-77/78/94 |
| 06 | Android static analysis | OWASP MASTG |
| 07 | Business logic / CRUD integrity | WSTG-BUSLOGIC |
| 08 | PII / transport / client exposure | OWASP API #3 BOPLA, CWE-200 |
| 09 | iOS / mobile | OWASP MASTG/MASVS |
| 10 | Scope, methodology, dedupe | engagement RoE best practice |
| 11 | Hardened targets (WAF/rate-limit) | testing methodology |
| 13 | Kali tool playbook (which tool for which bug) | tool docs: nuclei/ffuf/sqlmap/nmap/… |
| 12 | XSS / client injection | WSTG-CLNT, CWE-79 |
| 14 | File upload | WSTG-BUSLOGIC-09, CWE-434 |
| 15 | SSRF | OWASP API #7, CWE-918 |
| 16 | Verb tampering / authz matrix | WSTG-CONFIG-06 |
| 17 | CSRF / clickjacking | CWE-352/1021 |
| 18 | Server-Side Template Injection (SSTI) | WSTG-INPV-18, CWE-1336/94 |
| 19 | XML External Entity (XXE) | WSTG-INPV-07, OWASP API, CWE-611 |
| 20 | Insecure deserialization | OWASP Deserialization Cheat Sheet, CWE-502 |
| 21 | GraphQL API security | OWASP API Top 10, WSTG-APIT-01 |
| 22 | Path traversal / LFI | WSTG-ATHZ-01, CWE-22/98 |
| 23 | CORS misconfiguration | WSTG-CLNT-07, CWE-942 |
| 24 | OAuth 2.0 / OIDC / SSO | WSTG-ATHN, RFC 6749/6819, CWE-601/347 |
| 25 | Race conditions (TOCTOU) | WSTG-BUSLOGIC-06/09, CWE-362/367 |
| 26 | Open redirect | OWASP Unvalidated Redirects Cheat Sheet, CWE-601 |
| 27 | Subdomain takeover / dangling DNS | OWASP WSTG-CONFIG, CWE-350 |
| 28 | Recon & attack-surface mapping | OWASP WSTG-INFO, OSSTMM |

## Tooling referenced in the cards
Standard Kali / community tools: nuclei, ffuf, sqlmap, nmap, nikto, hydra, gobuster, wpscan,
katana, dalfox, jwt_tool, hashcat, john, Burp Suite (Repeater/Intruder/Turbo Intruder/Autorize),
jadx/apktool, Frida/objection, mobsfscan. Recon & exploitation helpers cited in the newer cards:
subfinder, amass, httpx, crt.sh, gau/waybackurls, feroxbuster, whatweb, subjack (takeover),
ysoserial / ysoserial.net / phpggc (deserialization gadgets), Clairvoyance (GraphQL schema).

## Related projects by the author
- **omniscience_pro** — the original general-purpose offline RAG this security-focused spin-off
  descends from: https://github.com/Saptarshi-Nag189/omniscience_pro
- **pdf-to-llm-plugin** — convert PDFs (scope docs, manuals, standards) into clean LLM-ready
  Markdown you can drop into `cards/` and re-ingest: https://github.com/Saptarshi-Nag189/pdf-to-llm-plugin

## Design lineage
The two-model cooperative verifier pattern (a skeptic model re-checking a generator's output)
was inspired by multi-agent skeptic/reflection designs; this implementation is self-contained,
local-Ollama-only, and rewritten for security-finding verification.
