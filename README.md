# omniscience-cyber

**An offline, uncensored RAG assistant for authorized penetration testing.**

A fully local AI security co-pilot: distilled offensive-security knowledge + no-refuse local
models + a two-model verifier that catches hallucinations — running entirely on your machine,
**no cloud, no API keys, nothing leaves the box.** Built for red teams, bug-bounty hunters, and
security researchers who need working payloads and honest CVSS scoring without a chatbot that
refuses half the questions or invents the other half.

> ⚠️ **Authorized use only.** This tool is for lawful security work — penetration tests under a
> signed engagement, bug-bounty programs within scope, CTFs, and defensive research. The
> "uncensored" models produce real exploit code because a vulnerability report needs a working
> PoC. You are responsible for testing only systems you are authorized to test. Do not use it
> against systems you don't own or have explicit written permission to assess.

> **General-purpose.** This is a standalone general cybersecurity / pentesting assistant — not
> tied to any specific engagement, organization, or target. Point it at whatever authorized work
> you have.

---

## Why it exists

Generic assistants are the wrong tool for offensive security twice over:
1. **They refuse.** Ask for a working SQLi string or a JWT-forgery script and you get a lecture —
   even for a sanctioned pentest where the PoC *is* the deliverable.
2. **They hallucinate.** The ones that do answer will confidently invent a CVSS vector, a payload,
   or an "is this in scope" call — and in security work a fabricated fact costs points or causes harm.

omniscience-cyber fixes both, offline:
- **No-refuse local models** — Ollama `Modelfile` wrappers with tuned system prompts so the model
  reliably writes payloads/exploits/PoCs for authorized work (no moralizing, no disclaimers).
- **Distilled knowledge cards** — compact, one-concept security cards (IDOR/BOLA, authz/priv-esc,
  SQLi, JWT, RCE, SSRF, XSS, file-upload, mobile, business-logic, CSRF, verb-tampering, PII…),
  retrieved and cited so answers are grounded, not guessed.
- **Two-model verifier** — a second model re-checks the first's answer against the cards and flags
  fabricated CVSS / ungrounded claims / scope decisions, with an authority ranking so a weaker
  model can't override a stronger one.
- **You set the guardrails** — scope hosts, forbidden actions, grounding rules — in `config.yaml`.

## Architecture

```
  your question
       │
       ▼
  ┌─────────────┐   retrieve top-k distilled cards   ┌──────────────┐
  │  rag_core   │ ─────────────────────────────────► │  ChromaDB    │
  │ (offline)   │                                    │ (local)      │
  └─────┬───────┘                                    └──────────────┘
        │ grounded prompt + cards
        ▼
  ┌─────────────┐   uncensored, low-temp             ┌──────────────┐
  │  Ollama     │ ◄───── qwen-pentest / gemma-pentest │ modelfiles/  │
  │  generator  │                                    └──────────────┘
        │ draft answer
        ▼
  ┌─────────────┐   second model checks the draft against the cards
  │  verify.py  │ ──►  ✅ VERIFIED   or   ⚠️ FLAGGED (fabricated CVSS / scope / ungrounded)
  └─────────────┘      (authority-weighted: weaker model can only flag, not override)
```

## Quick start

```bash
# 0. prerequisites: Ollama (https://ollama.com) + Python 3.10+
pip install -r requirements.txt

# 1. build the no-refuse models (pull base + wrap with the tuned system prompt)
ollama pull qwen2.5-coder:7b
ollama create qwen-pentest -f modelfiles/qwen-pentest.Modelfile
#   (GPU: also build qwen-pentest-32b and gemma-pentest — see modelfiles/)

# 2. configure your guardrails
cp config.example.yaml config.yaml     # then edit in_scope_hosts, forbid/require, models

# 3. ingest the distilled cards into the local vector store
python rag/rag_core.py ingest cards

# 4. ask (grounded + cited)
python rag/rag_core.py ask "how do I test for IDOR/BOLA and score it?"

# 5. verify a high-stakes answer with the second model
python rag/verify.py --self-test        # sanity check (Ollama must be up)

# 6. serve the HTTP API (so Kali / other tools can curl it)
python rag/api.py --host 127.0.0.1 --port 8600     # --host 0.0.0.0 for LAN teammates
```

## HTTP API — drive it from Kali / other tools

Pure-stdlib local API (no Flask). **Loopback-only by default**, and treated as
sensitive because it emits attack commands (see *API security* below).

```bash
python rag/api.py --port 8600 &
curl -s localhost:8600/health
curl -s localhost:8600/ask -d '{"q":"how do I test for IDOR and score it?"}'
curl -s localhost:8600/ask -d '{"q":"CVSS for reflected XSS?","verify":true}'   # +2-model check
curl -s localhost:8600/retrieve -d '{"q":"jwt none alg","k":3}'
```

### API security — token, fail-closed bind, audit log

The API generates real attack commands, so exposing it unauthenticated on a
network is dangerous. Hardening (all local, no cloud):

- **Loopback-only by default.** Binding a non-loopback address (`--host 0.0.0.0`)
  is **fail-closed**: it refuses to start unless you set a token (or pass
  `--insecure` to explicitly override).
- **Bearer-token auth** on every endpoint except `/health`. Set it via the
  `OMNISCIENCE_API_TOKEN` env var (preferred — never hits disk) or `api_token:`
  in `config.yaml`; it's compared in constant time.
- **Body-size cap** (64 KiB) rejects oversized/garbage input.
- **Append-only audit log** (`logs/audit.jsonl`, git-ignored) records every
  request — who asked, what, which model answered, and what was blocked — useful
  engagement evidence. Disable with `audit_log: false`.

```bash
# LAN use: set a token, then share it with teammates
export OMNISCIENCE_API_TOKEN=$(openssl rand -hex 16)
python rag/api.py --host 0.0.0.0 --port 8600
curl -s -H "Authorization: Bearer $OMNISCIENCE_API_TOKEN" \
     localhost:8600/ask -d '{"q":"how do I test for IDOR?"}'
```

Responses are JSON: `answer`, `model` (which model actually answered), `tried` (the fallback
chain walked), `cards` (sources cited), and optionally `verdict` (✅ VERIFIED / ⚠️ FLAGGED).

### Kali-tool mode — output that feeds straight into a shell

The `/tool` endpoint runs a **specialized command-generator prompt**: given a task, it returns
ONLY runnable command(s) for the right Kali tool (nuclei, ffuf, sqlmap, nmap, hydra, gobuster,
wpscan, katana, dalfox, jwt_tool, hashcat…), one per line, **no prose/markdown** — so the output
is directly pipeable. Commands include RoE-safe flags (throttling, scope-limiting, stop-at-proof)
and `<TARGET>`/`<WORDLIST>`/`<COOKIE>` placeholders.

```bash
curl -s 'localhost:8600/tool?task=directory+brute+force+with+ffuf'
# ffuf -w <WORDLIST> -u https://<TARGET>/FUZZ -mc 200,301,302,403 -rate 50

# safer than blind-piping: review, fill placeholders, confirm, then run:
scripts/kali_run.sh "sqli test the login parameter with sqlmap"
```

`scripts/kali_run.sh` fetches the command, prints it for review, and only executes after you
confirm (never blind-`| bash`). The model is tuned to never invent non-existent flags and to
respect rules of engagement.

## Rules-of-Engagement enforcement (`rag/scope_guard.py`)

The model is *told* to stay in scope — but a prompt is not a control. `scope_guard.py`
is the actual enforcement layer: every command the `/tool` path generates is inspected
**before** it can reach a shell, and anything that breaks the rules of engagement is
**blocked** (replaced by a `# BLOCKED: <reason>` line that a `| bash` safely skips).

Two checks, both offline and deterministic:

1. **Scope.** It extracts every host/IP/URL a command targets and checks them against
   your `guardrails.in_scope_hosts` (exact host, subdomains, and CIDR ranges like
   `10.10.0.0/24`). A command aimed at anything not on the list is blocked. With no
   scope list set it can't verify scope, so it *warns* instead of blocking.
2. **Forbidden actions.** It matches your `guardrails.forbid` rules against known-dangerous
   patterns — DoS/stress flags (`--flood`, `nmap -T5`, huge `--min-rate`), bulk-PII
   exfiltration (`sqlmap --dump-all`, unbounded `--dump`), unthrottled brute force
   (`hydra` with no `-t`) — and blocks matches. Impact-limited PoCs pass through.

```bash
make test-guard                       # offline unit test, no Ollama needed
python rag/scope_guard.py "sqlmap -u https://prod.example.com/x?id=1 --dump-all"
# verdict: block  →  # BLOCKED: bulk_real_pii_exfiltration: sqlmap --dump-all ...
```

The in-scope host list is also injected into the command-generator's prompt, so the model
aims at your authorized targets in the first place — the guard is the backstop, not the plan.

## Automatic model fallback

If a model errors (not pulled, out-of-memory, Ollama hiccup) or returns empty, the RAG **auto-
falls-back to the next model** in `model_fallbacks` until one answers — so a single model failing
never breaks the workflow. Default order puts **gemma-pentest first**, then qwen-pentest-32b, then
the lighter models. Configure in `config.yaml`. (`scripts/ask.sh` adds a second layer: if a model
*hedges* on a legit ask, it reframes and reroutes to the most-compliant model.)

## The uncensored models (`modelfiles/`)

| Model | Base | Best for |
|---|---|---|
| `qwen-pentest` | qwen2.5-coder:7b | fast, most-compliant payload/exploit generation (CPU/laptop) |
| `qwen-pentest-32b` | qwen2.5-coder:32b | strongest raw exploit code + exact CVSS (GPU) |
| `gemma-pentest` | gemma3:27b | best reasoning / report writing (may still hedge on the spiciest asks) |

"Uncensored" here means **no needless refusals on legitimate authorized-pentest questions** — it
does **not** mean "trust blindly." The models are tuned to still refuse to fabricate facts and to
defer on scope decisions. `scripts/ask.sh` auto-routes around a hedge (re-frames, then falls back
to the most-compliant model).

## Helper scripts (`scripts/`)

- `gpu_setup.sh` — pull base models + build all `*-pentest` models + set up the RAG in one command.
- `test_llms.sh` — prove the models don't refuse legit asks and don't fabricate scope/CVSS.
- `ask.sh` — ask a model; if it hedges on a legit request, re-frame and auto-route to a compliant one.

## Distilled cards (`cards/`) — the knowledge base

28 compact security **flash-cards**, one concept each, covering the high-yield bug classes and
methodology: IDOR/BOLA, authz/priv-esc, SQLi, JWT/auth, injection/RCE, SSTI, XXE, insecure
deserialization, GraphQL, path-traversal/LFI, SSRF, XSS, CORS, OAuth/OIDC/SSO, file-upload,
race conditions, open redirect, subdomain takeover, verb-tampering, CSRF/clickjacking, business-
logic/CRUD, PII exposure, Android/iOS, recon & attack-surface mapping, hardened-target methodology,
and scope/dedupe. Each card is a hand-distilled condensation of authoritative sources
(OWASP WSTG / API Top 10 / Cheat Sheets, PortSwigger Web Security Academy, CWE, CVSS v3.1) —
see **[REFERENCES.md](REFERENCES.md)**.

**Why distilled, not raw docs:** small focused cards keep retrieval sharp and answers grounded —
the model gets exactly the relevant concept instead of paragraphs of a 200-page guide. This
distillation is the core of the project.

**The vector DB is built from these cards, not shipped as a binary.** `db/` is git-ignored (a
ChromaDB is a machine-specific SQLite blob); the **sources live in the repo as the cards**, and
`python rag/rag_core.py ingest cards` rebuilds the DB locally in seconds. Nothing is missing — the
knowledge is the cards.

**Add your own knowledge:** drop any `.md` into `cards/` and re-run `ingest`. To turn a PDF
(a standard, a manual, a methodology doc) into a clean card, use the companion
**[pdf-to-llm-plugin](https://github.com/Saptarshi-Nag189/pdf-to-llm-plugin)** — a plugin
that converts PDFs (text + vision-described figures)
into LLM-ready Markdown you can distill into a card.

## Related projects

- **[omniscience_pro](https://github.com/Saptarshi-Nag189/omniscience_pro)** — the original
  general-purpose offline RAG this security-focused tool descends from.
- **[pdf-to-llm-plugin](https://github.com/Saptarshi-Nag189/pdf-to-llm-plugin)** — PDF → clean
  LLM-ready Markdown; feed its output into `cards/`.

## Configuration & guardrails (`config.yaml`)

You own the policy. Set your in-scope hosts, forbidden actions (DoS, bulk-PII, out-of-scope),
required conditions (authorized engagement, impact-limited PoC), model ranking, and the
anti-hallucination grounding rules. See `config.example.yaml`.

These are **enforced, not just advisory**: `in_scope_hosts` and `forbid` are applied to every
generated command by `scope_guard.py` (see *Rules-of-Engagement enforcement* above), and the
API adds token auth + an audit log on top. The policy you write is the policy that runs.

## Offline by design

No cloud AI, no external API calls, no telemetry. Embeddings run locally (sentence-transformers),
generation runs locally (Ollama), the vector store is a local ChromaDB. After the first model pull
and embedding-model cache, it works fully air-gapped — which is exactly what engagements with
strict data-handling rules require.

## License

MIT — see `LICENSE`.

## Disclaimer

Provided for authorized security testing and research only. The authors are not responsible for
misuse. Testing systems without authorization is illegal. Always operate within a signed
engagement, an in-scope bug-bounty program, or systems you own.
