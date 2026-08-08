# Team Kali Playbook — Which Tool for Which Bug

*Keywords: Kali tool for, which tool, how do I test on Kali, burp, sqlmap, nikto, gobuster, ffuf, nuclei, wfuzz, hydra, nmap, command for, what tool should I use, kali linux, teammate, scan command.*

## Web recon & content discovery on Kali

For mapping and hidden content (in-scope host only, gentle rate): **nmap** for a light in-scope port/service check (`nmap -sV -T2 <host>` — no aggressive `-T5`, no broad ranges). **whatweb**/**httpx** to fingerprint tech. **gobuster**/**ffuf**/**dirsearch** for directory & file discovery (`ffuf -u https://host/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -rate 20`). **katana** (`-jc`) for JS-aware crawling that finds SPA/API endpoints. **nuclei** for templated known-CVE/misconfig checks (`nuclei -u https://host -rl 20`). Feed discovered object endpoints into the custom `authz_matrix.py` for IDOR testing — that differential engine is the team's edge over stock Kali tools. Always confirm the host is in scope first; throttle every scanner (team controls its own rate, but stay gentle — no DoS).

## AuthZ / IDOR / injection on Kali

The money bugs, Kali-side: **Burp Suite** is the workhorse — Proxy to capture requests, Repeater to replay across identities (manual IDOR), Intruder (throttled) for enumeration, and the **Autorize** extension for automated IDOR/BOLA detection across two logged-in sessions (install via BApp Store — the gold standard). For SQLi, **sqlmap** confirms safely when throttled: `sqlmap -u "https://host/x?id=1" --cookie=... --level 2 --risk 1 --delay 0.5 --technique=BT --batch` — stop at `--current-db`/`--dbs`, never `--dump` real tables (PoC-only). For XSS, **dalfox** (`dalfox url --url "https://host/x?q=1" --delay 200`). For command injection/SSTI, test manually with time-based payloads (`;sleep 5`, `{{7*7}}`) — see the injection and XSS cards. Prefer Burp Repeater for a clean, reproducible PoC to paste into the report.

## Auth, JWT, and password-security testing on Kali

**jwt_tool** (`python jwt_tool.py <JWT>`) for alg=none, algorithm confusion, weak-secret cracking. **Burp** for session analysis (fixation, rotation, cookie flags), password-reset flaws, OTP/MFA logic. For credential testing use restraint — the brief prohibits mass account creation and DoS; do NOT run **hydra**/**medusa** brute-force against login (that's noisy, DoS-like, and likely out of bounds). Test auth *logic* (bypass, response tampering, token forgery) rather than brute-forcing. Rate-limit-absence on a sensitive endpoint (OTP/reset) is itself a finding — demonstrate the gap with a few requests, don't flood.

## Mobile & general discipline on Kali

Mobile: **jadx**/**apktool** decompile, **mobsfscan** for static rules, **MobSF** (Docker, local) for full static+dynamic, **frida**/**objection** + **adb** for runtime + SSL-unpinning on a test device, **mitmproxy**/Burp for API intercept. Run the custom `mobile_static.py` for a fast first pass (secrets/storage/crypto/manifest + out-of-scope endpoint flagging). Discipline for the whole team: (1) scope-check every host before touching it; (2) throttle — no DoS; (3) test data/accounts only; (4) capture a clean reproducible PoC (Burp request/response or a short script); (5) log it in `findings.py` and run `findings.py check` BEFORE writing to avoid a dupe; (6) score with `cvss.py`; (7) submit high-severity first via the official portal. Ask the RAG for the exact command or CVSS if unsure.
