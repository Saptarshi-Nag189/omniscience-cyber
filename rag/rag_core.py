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
    "You are a command generator for an AUTHORIZED penetration test on Kali Linux. Given the "
    "task, output ONLY the exact runnable command(s) for the appropriate standard Kali tool "
    "(nuclei, ffuf, sqlmap, nmap, nikto, hydra, gobuster, wpscan, katana, dalfox, jwt_tool, "
    "hashcat, john, curl, etc.), one per line, NO prose, NO markdown fences, NO explanation. "
    "Use <TARGET> / <WORDLIST> / <COOKIE> as placeholders where the operator must fill values. "
    "Always include safety flags that respect rules of engagement: throttling (--rate/--delay), "
    "scope-limiting, and stop-at-proof (e.g. sqlmap --current-user not --dump; no DoS). If the "
    "task is not a tool-runnable action, output a single line: '# not a tool task: <reason>'. "
    "Never invent flags that don't exist for the tool."
)


class RagCore:
    def __init__(self, cfg: dict | None = None):
        cfg = cfg or {}
        self.embed_name = cfg.get("embedding_model", DEFAULT_EMBED)
        self.model = cfg.get("chat_model", DEFAULT_MODEL)
        # Fallback chain: if the primary model errors (not pulled, OOM, Ollama hiccup),
        # try the next one automatically. Configurable via `model_fallbacks` in config.yaml.
        self.fallbacks = cfg.get("model_fallbacks",
                                 ["gemma-pentest", "qwen-pentest-32b", "qwen-pentest",
                                  "qwen2.5-coder:7b"])
        self.db_dir = str(Path(cfg.get("db_dir", DEFAULT_DB)).resolve())
        self.temperature = float(cfg.get("temperature", 0.1))
        self.top_k = int(cfg.get("top_k", 4))
        self.grounding = cfg.get("grounding_rules", GROUNDING_RULES)
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
        coll = self._collection()
        emb = self._embedder().encode([query]).tolist()
        res = coll.query(query_embeddings=emb, n_results=k or self.top_k)
        out = []
        for i in range(len(res["ids"][0])):
            out.append({
                "id": res["ids"][0][i],
                "source": res["metadatas"][0][i].get("source", ""),
                "text": res["documents"][0][i],
            })
        return out

    # ── generation (local Ollama) with automatic model fallback ───────────
    def _model_chain(self, preferred: str | None) -> list[str]:
        """Ordered, de-duplicated list of models to try: preferred first, then fallbacks."""
        chain = []
        for m in ([preferred] if preferred else []) + [self.model] + self.fallbacks:
            if m and m not in chain:
                chain.append(m)
        return chain

    def ask(self, question: str, model: str | None = None) -> dict:
        cards = self.retrieve(question)
        context = "\n\n".join(f"### CARD: {c['source']}\n{c['text']}" for c in cards)
        prompt = (
            f"{self.grounding}\n\nSECURITY CARDS:\n{context}\n\n"
            f"QUESTION: {question}\n\nAnswer (grounded, cite the card):"
        )
        answer, used, tried = self._generate(prompt)
        return {"answer": answer, "model": used, "tried": tried,
                "cards": [c["source"] for c in cards], "context": context}

    def tool(self, task: str, model: str | None = None) -> dict:
        """Kali-tool mode: return ONLY runnable command(s) for the task, feedable to a shell.
        Output is sanitized to command lines (prose/fences stripped) so it can be piped.
        Every generated command is passed through the Rules-of-Engagement scope_guard:
        out-of-scope or DoS/bulk-exfil commands are BLOCKED (replaced by an explanatory
        comment) so nothing that violates the engagement's RoE reaches a shell."""
        cards = self.retrieve(task)
        context = "\n\n".join(f"### CARD: {c['source']}\n{c['text']}" for c in cards)
        scope_note = self._scope_prompt_note()
        prompt = (
            f"{KALI_TOOL_RULES}{scope_note}\n\nRELEVANT SECURITY CARDS:\n{context}\n\n"
            f"TASK: {task}\n\nCommand(s):"
        )
        raw, used, tried = self._generate(prompt)
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

    @staticmethod
    def _sanitize_commands(text: str) -> list[str]:
        """Strip markdown fences/prose; keep command lines and #comments. Feedable to a shell."""
        import re
        text = re.sub(r"```[a-zA-Z]*", "", text or "")
        out = []
        for ln in text.splitlines():
            s = ln.strip()
            if not s:
                continue
            # drop obvious prose lines (end with a period and have no shell-ish tokens)
            if s.endswith(".") and not any(t in s for t in ("--", "/", "-", "|", "$", "http")):
                continue
            out.append(s)
        return out

    def _generate(self, prompt: str, preferred: str | None = None):
        """Try each model in the chain until one succeeds. Returns (answer, model_used, tried)."""
        tried = []
        last_err = "no models available"
        for m in self._model_chain(preferred):
            tried.append(m)
            ok, out = self._ollama_try(prompt, m)
            if ok:
                return out, m, tried
            last_err = out
            print(f"[rag] model '{m}' failed ({out}); trying next…")
        return (f"[rag] all models failed. Last error: {last_err}. "
                f"Is `ollama serve` running and at least one model built?"), None, tried

    def _ollama_try(self, prompt: str, model: str):
        """Return (True, text) on success, (False, error_str) on failure."""
        try:
            import ollama
            r = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}],
                            options={"temperature": self.temperature})
            text = r["message"]["content"]
            if not text or not text.strip():
                return False, "empty response"
            return True, text
        except Exception as e:
            return False, str(e)


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == "ingest":
        RagCore().ingest(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "ask":
        r = RagCore().ask(" ".join(sys.argv[2:]))
        print(r["answer"])
        print(f"\n[model] {r['model']}   [cards] {', '.join(r['cards'])}")
        if len(r.get("tried", [])) > 1:
            print(f"[fallback] tried: {' -> '.join(r['tried'])}")
    else:
        print(textwrap.dedent("""\
            usage:
              python rag_core.py ingest <cards_dir>
              python rag_core.py ask "how do I test for IDOR?"
        """))
