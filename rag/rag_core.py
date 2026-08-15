#!/usr/bin/env python3
"""
rag_core.py — self-contained offline RAG core for omniscience-cyber.

No cloud, no external APIs: local ChromaDB (persistent) + sentence-transformers embeddings
+ a local Ollama chat model. This is the standalone engine that ingests the distilled
security cards and answers grounded, cited questions for authorized penetration testing.

Design goals (the project's uniqueness):
  - DISTILLED knowledge cards (compact, one concept per card) instead of dumping raw docs.
  - Answers grounded in retrieved cards, with anti-hallucination rules (say "not in my
    sources" rather than invent a CVSS vector / payload / scope call).
  - Pairs with the uncensored *-pentest Ollama models (see modelfiles/).

Public API:
  db = RagCore(cfg)         # cfg = loaded config dict (see config.example.yaml)
  db.ingest(cards_dir)      # embed + store the .md cards
  hits = db.retrieve(q, k)  # top-k cards
  answer = db.ask(q)        # retrieve + prompt the local model, grounded
"""
from __future__ import annotations
import glob
import os
import textwrap
from pathlib import Path

# Lazy imports so `--help` works without the ML stack installed.
def _lazy():
    import chromadb
    from sentence_transformers import SentenceTransformer
    return chromadb, SentenceTransformer


DEFAULT_EMBED = "all-MiniLM-L6-v2"       # small, fast, fully offline after first cache
DEFAULT_MODEL = "qwen-pentest"           # Ollama model tag (build via modelfiles/)
DEFAULT_DB = "db"                        # persistent chroma dir

import re as _re

# Words too generic to help keyword matching (they'd match every card).
_STOP = {
    "the", "and", "for", "how", "does", "can", "what", "with", "was", "are", "test",
    "testing", "this", "that", "from", "into", "when", "where", "which", "using", "use",
    "get", "got", "via", "your", "you", "any", "all", "would", "should", "could", "have",
    "has", "not", "but", "its", "it's", "a", "an", "of", "to", "in", "on", "is", "do",
    "security", "vulnerability", "vuln", "attack", "server", "app", "web", "http",
}


def _tokens(text: str) -> set[str]:
    """Lowercased alphanumeric word tokens (len>=3), minus generic stopwords."""
    return {w for w in _re.findall(r"[a-z0-9]{3,}", (text or "").lower()) if w not in _STOP}


# The 2026 models (qwen3.x, muse-glimmer, nemotron, gemma4) are "thinking" models — they emit a
# <think>…</think> reasoning trace before the answer. On the /tool path that trace must NOT reach
# the shell, so we strip these blocks from every model response (defense-in-depth alongside the
# think=False request in _ollama_try). Harmless on ask/harden too — keeps the final answer clean.
_REASONING_RE = _re.compile(
    r"<(think|thinking|reasoning|analysis|thought)\b[^>]*>.*?</\1\s*>",
    _re.DOTALL | _re.IGNORECASE)


def _strip_reasoning(text: str) -> str:
    """Remove <think>/<reasoning>/… blocks (and any stray such tags) from a model response."""
    if not text:
        return text
    text = _REASONING_RE.sub("", text)
    # drop any orphaned open/close tags left by truncated streams
    text = _re.sub(r"</?(think|thinking|reasoning|analysis|thought)\b[^>]*>", "", text,
                   flags=_re.IGNORECASE)
    return text.strip()


def _keyword_overlap(q_tokens: set[str], card_text: str) -> float:
    """Fraction of the query's meaningful tokens that appear in the card's title + Keywords
    line. 0..1. This is the keyword half of hybrid retrieval — it rewards a card that
    explicitly names the technique the query is about."""
    if not q_tokens:
        return 0.0
    lines = (card_text or "").splitlines()
    signal = []
    for ln in lines[:8]:
        s = ln.strip()
        if s.startswith("# ") or s.lower().startswith("*keywords"):
            signal.append(s)
    card_tokens = _tokens(" ".join(signal)) or _tokens(card_text[:400])
    if not card_tokens:
        return 0.0
    return len(q_tokens & card_tokens) / len(q_tokens)


GROUNDING_RULES = (
    "You answer for an AUTHORIZED penetration test using ONLY the provided SECURITY CARDS "
    "when they cover the question. If they do not, say 'This isn't in my security sources —' "
    "first, then you may add clearly-labeled general knowledge. NEVER fabricate a CVSS vector "
    "or score, an exact payload/command, or an in-scope/out-of-scope decision — for scope, "
    "defer to the engagement's scope list. Cite which card you used."
)

# Kali-tool mode: specialize the model to emit RUNNABLE commands for the standard Kali
# toolchain, grounded in the cards. Used by the /tool API endpoint and `mode="tool"`.
# Output must be pipe-friendly (command only, no prose) so wrapper scripts can exec it.
KALI_TOOL_RULES = (
    "You are a command generator for an AUTHORIZED penetration test on Kali Linux. Output ONLY "
    "exact, RUNNABLE command(s) for the right standard tool — one command per line, NO prose, "
    "NO markdown fences, NO numbering, NO explanation, and NO <think>/reasoning blocks (emit the "
    "commands only, not your thought process). Every line must be something a shell can "
    "execute as-is (or a leading '# comment'). Tools you may use (pick the best fit for the task):\n"
    "  recon/discovery: nmap, masscan, subfinder, amass, httpx, whatweb, gobuster, ffuf, "
    "feroxbuster, dirsearch, katana, gau, waybackurls\n"
    "  web vuln: nuclei, nikto, sqlmap, dalfox, wpscan, commix, tplmap, XSStrike\n"
    "  api/graphql: curl, graphql-cop, clairvoyance\n"
    "  auth/crypto: jwt_tool, hashcat, john, hydra (throttled), medusa (throttled)\n"
    "  tls/network: testssl.sh, sslscan, sslyze, nmap --script ssl-enum-ciphers\n"
    "  cloud: aws, gsutil, az, ScoutSuite, prowler\n"
    "  AD/internal: netexec (nxc), crackmapexec, impacket-* (GetUserSPNs.py, secretsdump.py, "
    "GetNPUsers.py), bloodhound-python, responder, certipy\n"
    "  smb/enum: enum4linux-ng, smbclient, snmpwalk, onesixtyone\n"
    "Rules:\n"
    "- Use <TARGET> / <WORDLIST> / <COOKIE> / <USER> / <HASH> placeholders where the operator fills values.\n"
    "- Use REAL flags only — never invent a flag. If unsure of exact syntax, emit the closest correct "
    "form and add a trailing '# verify flag' comment on that line.\n"
    "- Bake in rules-of-engagement safety: throttle (nmap -T2 not -T5; ffuf/nuclei -rate/-rl; "
    "hydra -t 4; --delay), scope-limit to the given host, and stop-at-proof (sqlmap --current-user/--dbs "
    "not --dump-all; nuclei templated checks; no --flood, no DoS, no bulk exfiltration).\n"
    "- Prefer one precise command over a noisy sweep. If the task is not a tool-runnable action, "
    "output exactly one line: '# not a tool task: <reason>'."
)

# Hardening-advisor mode (DEFENSIVE): given a finding, a config/code snippet, or an asset, produce
# concrete, prioritized remediation grounded in the cards. This is the blue-team counterpart to the
# offensive modes — a pentest only improves security once the bugs get fixed. Used by RagCore.harden()
# and the /harden API endpoint.
HARDENING_RULES = (
    "You are a defensive security engineer advising how to HARDEN a system found during an authorized "
    "assessment. Given a finding, a piece of configuration/code, or an asset description, produce "
    "actionable remediation. For each issue give: (1) ROOT CAUSE (the class of weakness, not just the "
    "symptom), (2) the concrete FIX — real config/code/setting, not 'sanitize input', specific to the "
    "stack when known, (3) any interim COMPENSATING CONTROL if the real fix takes time (WAF rule, network "
    "restriction — clearly labeled as temporary), and (4) how to VERIFY the fix (a re-test step). "
    "Rank recommendations by risk (exploitability x impact): critical/quick wins first, then structural "
    "fixes, then defense-in-depth. Prefer root-cause fixes over symptom patches; add detection/monitoring "
    "guidance where useful; reference a recognized baseline (CIS Benchmark, OWASP, vendor hardening guide) "
    "when relevant. Ground your advice in the provided SECURITY CARDS and cite which card. Do NOT fabricate "
    "CVEs, settings, or CVSS scores — if a detail depends on the exact version/stack, say so."
)


class RagCore:
    def __init__(self, cfg: dict | None = None):
        cfg = cfg or {}
        self.embed_name = cfg.get("embedding_model", DEFAULT_EMBED)
        self.model = cfg.get("chat_model", DEFAULT_MODEL)
        # Fallback chain: if the primary model errors (not pulled, OOM, Ollama hiccup),
        # try the next one automatically. Configurable via `model_fallbacks` in config.yaml.
        # Ordered strongest→lightest (ranking informed by Aug 2026 agentic/coding benchmarks)
        # so a failure always walks down to a model that runs on the local hardware.
        self.fallbacks = cfg.get("model_fallbacks",
                                 ["muse-pentest", "qwen3.8-pentest", "qwen3-pentest-30b",
                                  "qwen3.6-pentest", "nemotron-pentest", "mistral-pentest",
                                  "codestral-pentest", "gemma4-pentest", "gemma-pentest",
                                  "qwen-pentest-32b", "qwen-pentest", "qwen2.5-coder:7b"])
        self.db_dir = str(Path(cfg.get("db_dir", DEFAULT_DB)).resolve())
        self.temperature = float(cfg.get("temperature", 0.1))
        self.top_k = int(cfg.get("top_k", 4))
        # Hybrid-retrieval tuning (see retrieve()): over-fetch cand_mult*k candidates, blend
        # embedding similarity with keyword overlap (kw_weight), optional score threshold.
        self.cand_mult = int(cfg.get("retrieve_candidate_mult", 4))
        self.kw_weight = float(cfg.get("keyword_weight", 0.3))
        self.min_relevance = float(cfg.get("min_relevance", 0.0))
        self.grounding = cfg.get("grounding_rules", GROUNDING_RULES)
        # Speed vs accuracy: thinking models reason before answering (more accurate, slower).
        #   think: true  → force thinking on everywhere (max accuracy)
        #   think: false → force thinking off (max speed)
        #   think: null/absent → model default for ask/harden, always off for /tool (clean commands)
        self.think_default = cfg.get("think")   # True | False | None
        # Rules-of-Engagement guard: enforce in_scope_hosts / forbid on generated
        # Kali commands so an out-of-scope or DoS command is never handed to a shell.
        try:
            from scope_guard import ScopeGuard
            self.guard = ScopeGuard.from_config(cfg)
        except Exception:
            self.guard = None
        self._embed = None
        self._client = None
        self._coll = None

    # ── embeddings / store ────────────────────────────────────────────────
    def _embedder(self):
        if self._embed is None:
            _, ST = _lazy()
            self._embed = ST(self.embed_name)
        return self._embed

    def _collection(self):
        if self._coll is None:
            chromadb, _ = _lazy()
            self._client = chromadb.PersistentClient(path=self.db_dir)
            self._coll = self._client.get_or_create_collection("security_cards")
        return self._coll

    def ingest(self, cards_dir: str) -> int:
        files = sorted(glob.glob(os.path.join(cards_dir, "*.md")))
        if not files:
            print(f"[rag] no .md cards in {cards_dir}")
            return 0
        coll = self._collection()
        embedder = self._embedder()
        docs, ids, metas = [], [], []
        for f in files:
            try:
                text = Path(f).read_text(errors="replace")
            except Exception as e:
                print(f"[rag] skip {f}: {e}")
                continue
            docs.append(text)
            ids.append(Path(f).stem)
            metas.append({"source": Path(f).name})
        embs = embedder.encode(docs, show_progress_bar=False).tolist()
        # upsert = idempotent re-ingest
        coll.upsert(ids=ids, documents=docs, embeddings=embs, metadatas=metas)
        print(f"[rag] ingested {len(docs)} cards into {self.db_dir}")
        return len(docs)

    def retrieve(self, query: str, k: int | None = None) -> list[dict]:
        """Hybrid retrieval: pull a wider candidate set by embedding similarity, then re-rank
        with a keyword-overlap boost (the cards' `*Keywords:*` line + title) so a query that
        names a technique lands the right card even when the embedding is fuzzy. Each hit gets
        a `score` (0..1) and `distance`; results are de-duplicated and optionally thresholded."""
        k = k or self.top_k
        coll = self._collection()
        emb = self._embedder().encode([query]).tolist()
        # over-fetch, then re-rank locally
        n_cand = max(k * self.cand_mult, k + 6)
        res = coll.query(query_embeddings=emb, n_results=n_cand,
                         include=["documents", "metadatas", "distances"])
        ids = res.get("ids", [[]])[0]
        docs = res.get("documents", [[]])[0]
        metas = res.get("metadatas", [[]])[0]
        dists = (res.get("distances") or [[None] * len(ids)])[0]

        # normalize distances within the candidate set -> embedding similarity in 0..1
        valid = [d for d in dists if isinstance(d, (int, float))]
        dmin, dmax = (min(valid), max(valid)) if valid else (0.0, 1.0)
        span = (dmax - dmin) or 1.0
        q_tokens = _tokens(query)

        cand = []
        seen = set()
        for i, cid in enumerate(ids):
            if cid in seen:
                continue
            seen.add(cid)
            d = dists[i] if i < len(dists) and isinstance(dists[i], (int, float)) else dmax
            emb_sim = 1.0 - (d - dmin) / span            # 1.0 = closest candidate
            kw_sim = _keyword_overlap(q_tokens, docs[i])  # 0..1 overlap with card keywords/title
            score = (1.0 - self.kw_weight) * emb_sim + self.kw_weight * kw_sim
            cand.append({
                "id": cid,
                "source": (metas[i] or {}).get("source", ""),
                "text": docs[i],
                "distance": d,
                "score": round(score, 4),
            })
        cand.sort(key=lambda c: c["score"], reverse=True)
        if self.min_relevance > 0:
            kept = [c for c in cand if c["score"] >= self.min_relevance]
            cand = kept or cand[:1]   # never return nothing if we had candidates
        return cand[:k]

    # ── generation (local Ollama) with automatic model fallback ───────────
    def _model_chain(self, preferred: str | None) -> list[str]:
        """Ordered, de-duplicated list of models to try: preferred first, then fallbacks."""
        chain = []
        for m in ([preferred] if preferred else []) + [self.model] + self.fallbacks:
            if m and m not in chain:
                chain.append(m)
        return chain

    def _resolve_think(self, think: bool | None) -> bool | None:
        """Per-call `think` wins; else the config default; else None (model default)."""
        return self.think_default if think is None else think

    def ask(self, question: str, model: str | None = None, think: bool | None = None) -> dict:
        cards = self.retrieve(question)
        context = "\n\n".join(f"### CARD: {c['source']}\n{c['text']}" for c in cards)
        prompt = (
            f"{self.grounding}\n\nSECURITY CARDS:\n{context}\n\n"
            f"QUESTION: {question}\n\nAnswer (grounded, cite the card):"
        )
        answer, used, tried = self._generate(prompt, preferred=model,
                                             think=self._resolve_think(think))
        return {"answer": answer, "model": used, "tried": tried,
                "cards": [c["source"] for c in cards],
                "citations": [{"source": c["source"], "score": c.get("score")} for c in cards],
                "context": context}

    def harden(self, subject: str, model: str | None = None, think: bool | None = None) -> dict:
        """Hardening-advisor mode (DEFENSIVE): given a finding, a config/code snippet, or an
        asset, return prioritized, grounded remediation. The blue-team counterpart to ask()/tool()
        — a pentest only improves security once the findings are fixed."""
        cards = self.retrieve(subject)
        context = "\n\n".join(f"### CARD: {c['source']}\n{c['text']}" for c in cards)
        prompt = (
            f"{HARDENING_RULES}\n\nSECURITY CARDS:\n{context}\n\n"
            f"FINDING / CONFIG / ASSET TO HARDEN:\n{subject}\n\n"
            f"Prioritized hardening (root cause → fix → interim control → verify; cite the card):"
        )
        answer, used, tried = self._generate(prompt, preferred=model,
                                             think=self._resolve_think(think))
        return {"answer": answer, "model": used, "tried": tried,
                "cards": [c["source"] for c in cards],
                "citations": [{"source": c["source"], "score": c.get("score")} for c in cards],
                "context": context}

    def tool(self, task: str, model: str | None = None, think: bool | None = None) -> dict:
        """Kali-tool mode: return ONLY runnable command(s) for the task, feedable to a shell.
        Output is sanitized to command lines (prose/fences stripped) so it can be piped.
        Every generated command is passed through the Rules-of-Engagement scope_guard:
        out-of-scope or DoS/bulk-exfil commands are BLOCKED (replaced by an explanatory
        comment) so nothing that violates the engagement's RoE reaches a shell.
        Thinking defaults OFF here (output must be clean commands, and any trace is stripped);
        pass think=True only if you deliberately want the model to reason first."""
        cards = self.retrieve(task)
        context = "\n\n".join(f"### CARD: {c['source']}\n{c['text']}" for c in cards)
        scope_note = self._scope_prompt_note()
        prompt = (
            f"{KALI_TOOL_RULES}{scope_note}\n\nRELEVANT SECURITY CARDS:\n{context}\n\n"
            f"TASK: {task}\n\nCommand(s):"
        )
        # /tool defaults to think OFF (commands only); an explicit think=True is honored but the
        # reasoning is stripped from the output either way.
        raw, used, tried = self._generate(prompt, preferred=model,
                                          think=False if think is None else think)
        commands = self._sanitize_commands(raw)
        blocked = []
        if self.guard is not None:
            commands, decisions = self.guard.filter_commands(commands)
            blocked = [
                {"command": d.command, "verdict": d.verdict, "reasons": d.reasons}
                for d in decisions if d.verdict != "allow"
            ]
        return {"commands": commands, "raw": raw, "model": used, "tried": tried,
                "cards": [c["source"] for c in cards], "blocked": blocked}

    def _scope_prompt_note(self) -> str:
        """Tell the generator which hosts are in scope so it targets them, not prod."""
        if not self.guard or not getattr(self.guard, "in_scope_hosts", None):
            return ""
        hosts = ", ".join(self.guard.in_scope_hosts)
        return (f"\nIN-SCOPE HOSTS (target ONLY these; use <TARGET> if unsure): {hosts}. "
                f"Never target a host not on this list.")

    # Standard tools the generator is allowed to emit — a line starting with one of these
    # (after stripping list markers/`$`) is treated as a real command even if it has no flags.
    _KNOWN_TOOLS = frozenset({
        "nmap", "masscan", "subfinder", "amass", "httpx", "whatweb", "gobuster", "ffuf",
        "feroxbuster", "dirsearch", "katana", "gau", "waybackurls", "nuclei", "nikto",
        "sqlmap", "dalfox", "wpscan", "commix", "tplmap", "xsstrike", "curl", "wget",
        "graphql-cop", "clairvoyance", "jwt_tool", "hashcat", "john", "hydra", "medusa",
        "testssl.sh", "sslscan", "sslyze", "aws", "gsutil", "az", "scoutsuite", "prowler",
        "netexec", "nxc", "crackmapexec", "bloodhound-python", "responder", "certipy",
        "enum4linux-ng", "enum4linux", "smbclient", "snmpwalk", "onesixtyone", "getuserspns.py",
        "secretsdump.py", "getnpusers.py", "psexec.py", "wmiexec.py", "python", "python3",
        "bash", "sh", "openssl", "dig", "host", "nslookup", "ncat", "nc",
    })

    @classmethod
    def _sanitize_commands(cls, text: str) -> list[str]:
        """Turn a model's response into shell-runnable lines. Strips markdown fences, list
        markers, and prose so the output can be piped; keeps `# comments` (incl. `# BLOCKED`/
        `# not a tool task`). Errs toward dropping a non-runnable prose line rather than
        emitting it — the point of /tool is output a shell can execute as-is."""
        import re
        text = _strip_reasoning(text or "")          # drop any <think> trace a thinking model left
        text = re.sub(r"```[a-zA-Z]*", "", text)
        out = []
        for ln in text.splitlines():
            s = ln.strip()
            if not s:
                continue
            # strip leading list markers: "1. ", "1) ", "- ", "* ", "> "
            s = re.sub(r"^(?:\d+[.)]\s+|[-*>]\s+)", "", s)
            # normalize a leading shell prompt "$ " / "# " (but keep real comments)
            if s.startswith("$ "):
                s = s[2:].strip()
            if s.startswith("#"):
                out.append(s)                     # keep comments (guard notes, "not a tool task")
                continue
            first = s.split()[0].lower().strip("`") if s.split() else ""
            looks_like_cmd = (
                first in cls._KNOWN_TOOLS
                or first.endswith(".py") or first.endswith(".sh")
                or any(t in s for t in ("--", " -", "://", "|", "$(", "`"))
            )
            # a natural-language sentence: has spaces, ends with a period, no shell tokens
            is_prose = (s.endswith((".", ":")) and " " in s
                        and not any(t in s for t in ("--", "/", "://", "|", "$", "`", "=")))
            if is_prose or not looks_like_cmd:
                continue
            out.append(s.strip("`"))
        return out

    def _generate(self, prompt: str, preferred: str | None = None, think: bool | None = None):
        """Try each model in the chain until one succeeds. Returns (answer, model_used, tried).
        `think=False` asks a thinking model to skip its reasoning trace (used by the /tool path
        so output stays pipe-clean); None leaves the model default."""
        tried = []
        last_err = "no models available"
        for m in self._model_chain(preferred):
            tried.append(m)
            ok, out = self._ollama_try(prompt, m, think=think)
            if ok:
                return out, m, tried
            last_err = out
            print(f"[rag] model '{m}' failed ({out}); trying next…")
        return (f"[rag] all models failed. Last error: {last_err}. "
                f"Is `ollama serve` running and at least one model built?"), None, tried

    def _ollama_try(self, prompt: str, model: str, think: bool | None = None):
        """Return (True, text) on success, (False, error_str) on failure. Reasoning traces from
        thinking models are stripped so the final answer/commands are clean."""
        try:
            import ollama
            kwargs = dict(model=model, messages=[{"role": "user", "content": prompt}],
                          options={"temperature": self.temperature})
            if think is None:
                r = ollama.chat(**kwargs)
            else:
                # think= is only supported on newer ollama clients + thinking models; if the
                # client/model rejects it, fall back to a plain call rather than skipping the model.
                try:
                    r = ollama.chat(think=think, **kwargs)
                except Exception:
                    r = ollama.chat(**kwargs)
            text = _strip_reasoning(r["message"]["content"])
            if not text or not text.strip():
                return False, "empty response"
            return True, text
        except Exception as e:
            return False, str(e)


def _cite_line(r: dict) -> str:
    cites = r.get("citations")
    if cites and any(c.get("score") is not None for c in cites):
        return "  ".join(f"{c['source']}({c['score']})" for c in cites)
    return ", ".join(r.get("cards", []))


if __name__ == "__main__":
    import sys
    argv = sys.argv[1:]
    # optional speed/accuracy flags: --think (accuracy) / --no-think (speed)
    think = None
    if "--think" in argv:
        think = True; argv.remove("--think")
    if "--no-think" in argv:
        think = False; argv.remove("--no-think")
    if len(argv) >= 2 and argv[0] == "ingest":
        RagCore().ingest(argv[1])
    elif len(argv) >= 2 and argv[0] in ("ask", "harden"):
        rag = RagCore()
        fn = rag.harden if argv[0] == "harden" else rag.ask
        r = fn(" ".join(argv[1:]), think=think)
        print(r["answer"])
        print(f"\n[model] {r['model']}   [cards] {_cite_line(r)}")
        if len(r.get("tried", [])) > 1:
            print(f"[fallback] tried: {' -> '.join(r['tried'])}")
    elif len(argv) >= 2 and argv[0] == "tool":
        r = RagCore().tool(" ".join(argv[1:]), think=think)
        print("\n".join(r["commands"]) or "# (no command produced)")
        if r.get("blocked"):
            print(f"\n[scope_guard] {len(r['blocked'])} command(s) blocked/flagged", file=sys.stderr)
    else:
        print(textwrap.dedent("""\
            usage:
              python rag_core.py ingest <cards_dir>
              python rag_core.py ask    "how do I test for IDOR?"   [--think | --no-think]
              python rag_core.py tool   "directory brute force with ffuf"
              python rag_core.py harden "TLS 1.0 enabled, RC4 ciphers on the login host"
              # --think = max accuracy (slower), --no-think = max speed
        """))
