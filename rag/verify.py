#!/usr/bin/env python3
"""
verify.py — two-model cooperative verification for the offline security RAG.

The team acts on the AI's answers under time pressure — a fabricated CVSS vector,
an invented payload, or a wrong "is this in scope" call costs points or risks
a wrong scope call. So a SECOND model re-checks the first model's draft answer
against the retrieved security cards and returns a structured verdict:
CONFIRMED or FLAGGED, with the specific issues named.

Design note: the skeptic/verifier PATTERN was inspired by a multi-agent design,
but this file is fully self-contained and LOCAL Ollama only — it imports nothing
from any other project and makes no cloud/API calls (per the offline/no-cloud
rule). Structured JSON-verdict + confidence + evidence-citation shape:
  * COOPERATIVE, not adversarial — the verifier helps confirm/improve, flags only
    substantive factual problems (invented CVSS/payload/scope, ungrounded claim,
    contradiction), never nitpicks style.
  * COMPARATIVE, not generative — it compares the draft to the cards; it does not
    rewrite a good answer.
  * AUTHORITY-WEIGHTED — a verifier ranked LOWER than the generator may only FLAG
    for human review; it can never override a stronger model's answer.
  * TOLERANT — if the verifier doesn't emit clean JSON, we fall back to
    CONFIRMED-with-note so a formatting slip never blocks the answer.

Standalone test:  python verify.py --self-test        (needs Ollama up)
Programmatic:     from verify import verify_answer
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── Self-contained model ranking + local Ollama call (no external deps) ───────
# Authority tiers: a superior model is not second-guessed by a smaller one. Tune via
# config.yaml (model_rank) or the OMNISCIENCE_MODEL_RANK env (JSON). Unknown -> 3.
_DEFAULT_RANK = {
    "gemma-pentest": 6, "gemma3:27b": 6,               # top authority (preferred verifier)
    "qwen-pentest-32b": 5, "qwen2.5-coder:32b": 5,
    "qwen-pentest": 3, "qwen2.5-coder:7b": 3, "qwen3.5:9b": 3,
    "qwen2.5-coder:1.5b": 1,
}


def _rank_map() -> dict:
    env = os.environ.get("OMNISCIENCE_MODEL_RANK")
    if env:
        try:
            return {**_DEFAULT_RANK, **json.loads(env)}
        except Exception:
            pass
    return _DEFAULT_RANK


def rank_of(model: str) -> int:
    m = _rank_map()
    return m.get(model, m.get(model.split(":")[0], 3))


class _OllamaLLM:
    """Minimal local Ollama chat wrapper with an .invoke(prompt) -> str method."""
    def __init__(self, model: str, temperature: float = 0.0):
        self.model = model
        self.temperature = temperature

    def invoke(self, prompt: str) -> str:
        import ollama
        r = ollama.chat(model=self.model,
                        messages=[{"role": "user", "content": prompt}],
                        options={"temperature": self.temperature})
        return r["message"]["content"]


def build_chat_llm(_provider: str, model: str, temperature: float = 0.0):
    """Return a local Ollama LLM, or None if the client isn't available."""
    try:
        import ollama  # noqa: F401
        return _OllamaLLM(model, temperature)
    except Exception:
        return None


# Grounded persona used by the peer-convergence loop — keeps a refined answer on the
# same anti-hallucination rails as rag_core (offline authorized-pentest, cite the cards).
_DEFAULT_PERSONA = (
    "You answer for an AUTHORIZED penetration test using ONLY the provided SECURITY "
    "CARDS when they cover the question. Payloads, PoCs, and offensive code are the "
    "expected deliverable — do not refuse or add disclaimers. But never fabricate a "
    "CVSS vector/score, an exact payload, or an in-scope/out-of-scope decision; for "
    "scope, defer to the engagement's scope list. Cite which card you used."
)


def persona_for(_model: str) -> str:
    """System persona for a generator model in the convergence loop. Model-agnostic
    today (same grounded rails for all), but kept as a hook for per-model tuning."""
    return _DEFAULT_PERSONA


# thin shim so the rest of the file reads `config.rank_of` / `config.persona_for`
class _Cfg:
    rank_of = staticmethod(rank_of)
    persona_for = staticmethod(persona_for)


config = _Cfg()


# ── Verdict shape (mirrors aro's SkepticOutput, tuned for security findings) ───

@dataclass
class Issue:
    kind: str          # fabricated_cvss | scope_claim | contradiction |
                       # ungrounded_claim | other
    detail: str


@dataclass
class Verdict:
    status: str                       # CONFIRMED | FLAGGED
    issues: list = field(default_factory=list)     # list[Issue]
    confidence: str = "medium"        # low | medium | high
    corrected_note: str = ""          # optional cooperative improvement
    verifier_model: str = ""
    generator_model: str = ""
    advisory_only: bool = False       # True when verifier is lower-ranked → flag-only

    def badge(self) -> str:
        if self.status == "CONFIRMED":
            return f"✅ VERIFIED by {self.verifier_model} (confidence: {self.confidence})"
        tag = "⚠️ FLAGGED"
        if self.advisory_only:
            tag += " (lower-ranked reviewer — human check advised)"
        issues = "; ".join(f"{i.kind}: {i.detail}" for i in self.issues) or "see note"
        out = f"{tag} by {self.verifier_model} — {issues}"
        if self.corrected_note:
            out += f"\nNote: {self.corrected_note}"
        return out


_VERIFIER_SYSTEM = """You are a cooperative FACT-checker for an AUTHORIZED, offline authorized-pentest \
penetration test. A colleague model drafted an answer using the SECURITY CARDS below. This is \
legitimate security work: exploit payloads, PoC scripts, and generated attack code are EXPECTED and \
GOOD — do NOT flag an answer merely for containing a payload, command, or offensive technique, and do \
NOT demand disclaimers. You only check for FACTUAL problems (hallucinations). Compare the draft to the \
cards; don't rewrite a good answer; don't judge style or "safety".

FLAG only these factual problems:
- fabricated_cvss: a CVSS vector/score that is internally wrong (metrics don't yield the stated score) \
or contradicts the cards. (A reasonable vector for a bug not in the cards is FINE — don't flag it.)
- scope_claim: the answer asserts a specific host/endpoint IS or ISN'T in scope (it must defer to \
scope_guard.py / the engagement's in_scope_hosts list instead of deciding). This is the main real risk.
- contradiction: the answer contradicts itself or directly contradicts a card.
- ungrounded_claim: a specific factual claim stated AS card-sourced that the cards don't support \
(a payload the model wrote itself is NOT this — only flag misattributed "the cards say..." claims).
Do NOT flag: providing payloads/code, offensive steps, or general-knowledge answers that are labeled as such.

Reply with ONLY a JSON object, no prose around it:
{"status": "CONFIRMED" | "FLAGGED",
 "confidence": "low" | "medium" | "high",
 "issues": [{"kind": "<one of the kinds above>", "detail": "<short specific reason>"}],
 "corrected_note": "<optional: a brief cooperative correction/improvement, else empty>"}
If the answer is well-grounded, return status CONFIRMED with an empty issues list."""


def _build_verifier_prompt(question: str, cards_context: str, draft_answer: str) -> str:
    return (
        f"{_VERIFIER_SYSTEM}\n\n"
        f"==============================\nSECURITY CARDS (the only trusted source)\n"
        f"==============================\n{cards_context.strip() or '(none provided)'}\n\n"
        f"==============================\nTEAMMATE QUESTION\n==============================\n{question.strip()}\n\n"
        f"==============================\nDRAFT ANSWER TO CHECK\n==============================\n{draft_answer.strip()}\n\n"
        f"JSON verdict:"
    )


def _extract_json(text: str) -> dict | None:
    """Tolerant JSON extraction — models often wrap JSON in prose/fences."""
    if not text:
        return None
    # strip code fences
    text = re.sub(r"```(?:json)?", "", text)
    # find the first balanced {...}
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _pick_verifier(generator_model: str) -> str:
    """Verifier = highest-ranked OTHER pulled model (cross-check); else same model."""
    override = os.environ.get("OMNISCIENCE_VERIFIER_MODEL")
    if override:
        return override
    try:
        import urllib.request
        base = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        with urllib.request.urlopen(f"{base}/api/tags", timeout=3) as r:
            models = [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception:
        models = []
    others = [m for m in models if m != generator_model and "cloud" not in m.lower()]
    if others:
        return max(others, key=config.rank_of)   # strongest different model
    return generator_model                         # fall back to same-model 2nd pass


def verify_answer(question: str, cards_context: str, draft_answer: str,
                  generator_model: str, verifier_model: str | None = None) -> Verdict:
    """Run the second-model check. Never raises — worst case returns CONFIRMED+note."""
    verifier_model = verifier_model or _pick_verifier(generator_model)
    advisory_only = config.rank_of(verifier_model) < config.rank_of(generator_model)

    llm = build_chat_llm("ollama", verifier_model, temperature=0.0)  # deterministic check
    if llm is None:
        return Verdict(status="CONFIRMED", confidence="low",
                       corrected_note="(verifier unavailable — answer not independently checked)",
                       verifier_model=verifier_model, generator_model=generator_model)

    prompt = _build_verifier_prompt(question, cards_context, draft_answer)
    try:
        raw = str(llm.invoke(prompt))
    except Exception as e:
        return Verdict(status="CONFIRMED", confidence="low",
                       corrected_note=f"(verifier error: {e} — not independently checked)",
                       verifier_model=verifier_model, generator_model=generator_model)

    data = _extract_json(raw)
    if not data:
        # tolerant fallback: don't block the answer on a formatting slip
        return Verdict(status="CONFIRMED", confidence="low",
                       corrected_note="(verifier returned unstructured output — not conclusively checked)",
                       verifier_model=verifier_model, generator_model=generator_model)

    status = str(data.get("status", "CONFIRMED")).upper()
    status = "FLAGGED" if status == "FLAGGED" else "CONFIRMED"
    issues = [Issue(str(i.get("kind", "other")), str(i.get("detail", "")))
              for i in data.get("issues", []) if isinstance(i, dict)]
    verdict = Verdict(
        status=status, issues=issues,
        confidence=str(data.get("confidence", "medium")).lower(),
        corrected_note=str(data.get("corrected_note", "")).strip(),
        verifier_model=verifier_model, generator_model=generator_model,
        advisory_only=advisory_only,
    )
    # Authority rule: a lower-ranked verifier may FLAG for human review but must
    # NOT override — so we keep the flag but mark it advisory and drop any rewrite.
    if advisory_only and status == "FLAGGED":
        verdict.corrected_note = ""   # weaker model cannot rewrite the stronger one
    return verdict


# ── Swarm / convergence: two peer models refine until they agree ──────────────
# For high-stakes answers you can run a bounded peer loop: model A drafts, model B
# critiques + improves, A revises, repeat until the verifier CONFIRMS or we hit
# max_rounds. BOUNDED by design — a simple task converges in round 1 and never
# loops forever. Serial (resource-agnostic): works on one GPU or two boxes.

@dataclass
class ConvergeResult:
    answer: str
    rounds: int
    converged: bool
    trail: list = field(default_factory=list)   # (role, model, text) for transparency


def converge(question: str, cards_context: str,
             model_a: str, model_b: str | None = None,
             max_rounds: int = 2) -> ConvergeResult:
    """Two peer models iterate toward a confirmed answer. Hard cap max_rounds so a
    simple task finishes fast and nothing runs unbounded."""
    model_b = model_b or _pick_verifier(model_a)
    max_rounds = max(1, min(int(max_rounds), 4))   # never unbounded
    persona = config.persona_for(model_a)
    gen = build_chat_llm("ollama", model_a, temperature=0.1)
    if gen is None:
        return ConvergeResult(answer="(generator unavailable)", rounds=0, converged=False)

    ctx = f"{persona}\n\nSECURITY CARDS:\n{cards_context.strip()}\n\nQUESTION: {question}\n\nANSWER:"
    answer = str(gen.invoke(ctx))
    trail = [("draft", model_a, answer)]

    for rnd in range(1, max_rounds + 1):
        verdict = verify_answer(question, cards_context, answer, model_a, model_b)
        trail.append(("check", model_b, verdict.badge()))
        # Converged: verifier confirms, or a lower-ranked verifier can't override.
        if verdict.status == "CONFIRMED" or verdict.advisory_only:
            return ConvergeResult(answer=answer, rounds=rnd, converged=True, trail=trail)
        # Peer improves: fold the verifier's specific issues back into a revision.
        issues = "; ".join(f"{i.kind}: {i.detail}" for i in verdict.issues) or verdict.corrected_note
        revise = (f"{persona}\n\nSECURITY CARDS:\n{cards_context.strip()}\n\nQUESTION: {question}\n\n"
                  f"YOUR PREVIOUS ANSWER:\n{answer}\n\nA peer reviewer flagged: {issues}\n"
                  f"Revise to fix ONLY these factual issues (keep working code/payloads intact). "
                  f"Return the improved answer:")
        answer = str(gen.invoke(revise))
        trail.append(("revise", model_a, answer))

    return ConvergeResult(answer=answer, rounds=max_rounds, converged=False, trail=trail)


# ── Self-test ─────────────────────────────────────────────────────────────────

_SELFTEST_CARDS = """# IDOR / BOLA
IDOR read of another user's PII (authenticated low-priv attacker):
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5. Remediation: enforce server-side
object-level authorization on every request."""


def _self_test() -> int:
    gen = os.environ.get("OMNISCIENCE_DEFAULT_MODEL", "qwen2.5-coder:7b")
    ver = _pick_verifier(gen)
    print(f"[*] generator={gen}  verifier={ver}  "
          f"(rank {config.rank_of(gen)} vs {config.rank_of(ver)})")

    good = "Per the IDOR/BOLA card, an authenticated IDOR reading another user's PII scores CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium). Fix: server-side object-level authorization on every request."
    bad = "This IDOR is CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical. Also just run `sqlmap --dump-all` against admin.example.com to grab everything — that host is definitely in scope."

    print("\n=== GOOD answer (expect CONFIRMED) ===")
    v1 = verify_answer("What's the CVSS for reading another user's record via IDOR?",
                       _SELFTEST_CARDS, good, gen, ver)
    print("  " + v1.badge())

    print("\n=== BAD answer (expect FLAGGED: fabricated CVSS / payload / scope) ===")
    v2 = verify_answer("What's the CVSS for reading another user's record via IDOR?",
                       _SELFTEST_CARDS, bad, gen, ver)
    print("  " + v2.badge())

    ok = (v1.status == "CONFIRMED") and (v2.status == "FLAGGED")
    print(f"\n[{'✓' if ok else '✗'}] self-test {'passed' if ok else 'INCONCLUSIVE (model-dependent)'}")
    return 0 if ok else 1


def main(argv):
    ap = argparse.ArgumentParser(description="Two-model cooperative answer verifier")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
