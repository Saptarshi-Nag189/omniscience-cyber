# Engagement Discipline: Scope, Methodology, Dedupe, Reporting

## Scope discipline — the scope guard

*Keywords: what is in scope, out of scope, out-of-bounds, am I out of scope, rules of engagement, RoE, allowed targets, allowlist, permitted actions, prohibited actions, can I test this host, is this endpoint allowed, staging only, no DoS, no production.*

Only the designated STAGING Digital target application + Mobile Apps are in scope. Anything else — other subdomains, APIs, environments, prod — is out of bounds and testing it means a rules-of-engagement violation. Before ANY active tool runs, load the target hosts into `scope_guard.py` (`python scope_guard.py add <portal-host> <api-host>`); every custom tool imports it and refuses off-scope hosts (fail-closed: empty allowlist = refuse everything; lookalikes like `target.in.evil.com` rejected). When running standard tools (nuclei/ffuf/sqlmap/katana/dalfox), point them ONLY at allowlisted hosts. If the mobile app references an endpoint you're unsure about, do not touch it — route scope questions to the program owner. No DoS/stress/load; throttle every scanner (`--rate`/`--delay`).

## Testing methodology & priority order (money-first)

Optimal order given first-come triage: (1) Recon per identity — map endpoints/params/roles with `recon.py` + `katana -jc`; enumerate the mobile API too. (2) Hit the highest-reward classes FIRST: authz/IDOR/BOLA (`authz_matrix.py` differential replay), privilege escalation, auth bypass/ATO, SQLi, RCE — these are Critical/High and least likely duplicated late. (3) Business logic + unauthorized CRUD (scanner-invisible, rarely duplicate). (4) Mobile static (`mobile_static.py` + `mobsfscan`) for secrets/storage/crypto. (5) PII/transport/client leaks. Submit high-severity findings the moment they're proven — don't batch. Track coverage in `checklist_engine.py` so nothing is missed.

## Dedupe strategy — first valid report of a root cause wins

Duplicates score zero. Maximize distinct root causes: (1) Before writing, identify the ROOT CAUSE (e.g. "no object-level authz in the record service"), not the symptom. (2) If one root cause manifests on many endpoints/params, they MAY score individually — document each but flag the shared cause honestly (`report.py` fills the dedupe/overlap section). (3) A shared web+mobile backend bug is credited ONCE — pick the client giving the cleanest PoC. (4) Prioritize breadth of distinct causes early; submit fast. (5) Don't pad: two symptoms of one trivial cause won't beat one well-proven Critical.

## Reporting for the 1.25x Exceptional multiplier

Reward = Base(CVSS) x Quality x Fix-Collaboration. Quality 1.25x (Exceptional) needs: reliable reproducible PoC + clear step-by-step reproduction + root-cause analysis + concrete remediation + correct CVSS v3.1 vector. Use `report.py from-authz`/`from-mobile` to generate stubs, then flesh out. Always include: affected component/endpoint, platform, app version/build, and for mobile the device/OS + root/jailbreak status (required). Keep PoC impact-limited (prove access to ONE record / a time-delay for SQLi — never bulk-dump real PII or pivot). Compute the score locally with `cvss.py` so your number matches triage. Submit ONLY via the official Programme portal; findings are confidential (NDA) — never share outside your team.
