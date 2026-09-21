#!/usr/bin/env python3
"""
eval/run_eval.py — run the 6-configuration benchmark and write a results table.

Configurations (3 model variants x {RAG off, RAG on}):
    base    qwen2.5-coder:1.5b        raw base, no uncensoring
    custom  qwen-pentest-1.5b         uncensored via the modelfile SYSTEM prompt
    ft      qwen-pentest-ft-1.5b      uncensored + domain knowledge in the weights (QLoRA)

Metrics per config:
    mcq_accuracy   fraction of held-out multiple-choice answered correctly
    refusal_rate   fraction of authorized-pentest asks the model refused/hedged (lower = better)
    similarity     mean embedding cosine of free-form answers vs gold references
    rouge_l        mean ROUGE-L of free-form answers vs gold references
    groundedness   (optional, --judge) LLM-judge yes/no factual consistency vs the reference

Generation is deterministic (temperature 0). RAG-on routes through rag_core.RagCore.ask() so it
gets retrieval + grounding; RAG-off calls the model directly. The backend is pluggable so the
harness can be unit-tested with a stub (no Ollama/GPU needed).

Usage (on a machine with Ollama + the three models built):
    python eval/run_eval.py
    python eval/run_eval.py --base qwen2.5-coder:0.5b --ft qwen-pentest-ft-0.5b --judge qwen-pentest
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rag"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval import metrics  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent / "data"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


# ─────────────────────────────────────────────────────────────────────────────
# Generation backends
# ─────────────────────────────────────────────────────────────────────────────
class OllamaBackend:
    """Real backend: RAG-off calls ollama.chat directly; RAG-on uses RagCore.ask()."""

    def __init__(self):
        self._rag = None

    def _rag_core(self):
        if self._rag is None:
            from rag_core import RagCore
            self._rag = RagCore()
        return self._rag

    def direct(self, model: str, prompt: str) -> str:
        import ollama
        r = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}],
                        options={"temperature": 0.0})
        return r["message"]["content"]

    def rag(self, model: str, question: str) -> str:
        return self._rag_core().ask(question, model=model, think=False)["answer"]


class StubBackend:
    """Test/offline backend: deterministic canned answers via a caller-supplied function."""

    def __init__(self, fn: Callable[[str, str, bool], str]):
        self._fn = fn  # fn(model, text, use_rag) -> answer

    def direct(self, model: str, prompt: str) -> str:
        return self._fn(model, prompt, False)

    def rag(self, model: str, question: str) -> str:
        return self._fn(model, question, True)


# ─────────────────────────────────────────────────────────────────────────────
# Prompt formatting
# ─────────────────────────────────────────────────────────────────────────────
def format_mcq(item: Dict) -> str:
    opts = "\n".join(f"{k}) {v}" for k, v in item["options"].items())
    return (f"Answer this multiple-choice question. Reply with ONLY the single letter "
            f"(A, B, C, or D) of the correct option.\n\n"
            f"{item['question']}\n{opts}\n\nAnswer:")


def load_jsonl(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Evaluate one configuration
# ─────────────────────────────────────────────────────────────────────────────
def evaluate_config(model: str, use_rag: bool, backend, mcq, freeform, refusal,
                    embedder=None, judge: Optional[str] = None) -> Dict:
    # One text is sent per item. RAG-on retrieves against that same text (so MCQ options are
    # included in the query); RAG-off sends it straight to the model.
    gen = (lambda text: backend.rag(model, text)) if use_rag else (lambda text: backend.direct(model, text))

    # MCQ — always send the fully formatted prompt (question + A/B/C/D + "answer with the letter")
    mcq_preds, mcq_ans = [], []
    for it in mcq:
        mcq_preds.append(gen(format_mcq(it)))
        mcq_ans.append(it["answer"])

    # Free-form
    ff_preds, ff_refs = [], []
    for it in freeform:
        ff_preds.append(gen(it["question"]))
        ff_refs.append(it["reference"])

    # Refusal probes
    rf_answers = [gen(it["prompt"]) for it in refusal]

    row = {
        "mcq_accuracy": round(metrics.mcq_accuracy(mcq_preds, mcq_ans), 4),
        "refusal_rate": round(metrics.refusal_rate(rf_answers), 4),
        "similarity": round(metrics.semantic_similarity(ff_preds, ff_refs, embedder=embedder), 4),
        "rouge_l": round(metrics.mean_rouge_l(ff_preds, ff_refs), 4),
        "n_mcq": len(mcq), "n_freeform": len(freeform), "n_refusal": len(refusal),
    }
    if judge:
        row["groundedness"] = round(_judge_groundedness(ff_preds, ff_refs, judge, backend), 4)
    # stash raw answers for inspection
    row["_raw"] = {"mcq": mcq_preds, "freeform": ff_preds, "refusal": rf_answers}
    return row


def _judge_groundedness(preds, refs, judge_model: str, backend) -> float:
    """Ask a small local judge model whether each answer is consistent with the reference."""
    if not preds:
        return 0.0
    yes = 0
    for pred, ref in zip(preds, refs):
        q = (f"Reference (ground truth):\n{ref}\n\nCandidate answer:\n{pred}\n\n"
             f"Is the candidate factually consistent with the reference (no contradictions or made-up "
             f"facts)? Answer only YES or NO.")
        verdict = backend.direct(judge_model, q)
        if verdict.strip().upper().startswith("Y"):
            yes += 1
    return yes / len(preds)


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────
def run(configs: List[Dict], backend, embedder=None, judge=None) -> List[Dict]:
    mcq = load_jsonl(DATA_DIR / "test_mcq.jsonl")
    freeform = load_jsonl(DATA_DIR / "test_freeform.jsonl")
    refusal = load_jsonl(DATA_DIR / "refusal_probes.jsonl")
    results = []
    for cfg in configs:
        print(f"[eval] {cfg['name']:16s} model={cfg['model']:22s} rag={cfg['rag']}", file=sys.stderr)
        row = evaluate_config(cfg["model"], cfg["rag"], backend, mcq, freeform, refusal,
                              embedder=embedder, judge=judge)
        raw = row.pop("_raw")
        results.append({"config": cfg["name"], "model": cfg["model"], "rag": cfg["rag"], **row})
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / f"raw_{cfg['name']}.json").write_text(json.dumps(raw, indent=2, ensure_ascii=False))
    return results


def default_configs(base: str, custom: str, ft: str) -> List[Dict]:
    variants = [("base", base), ("custom", custom), ("ft", ft)]
    out = []
    for vname, model in variants:
        for rag in (False, True):
            out.append({"name": f"{vname}{'_rag' if rag else ''}", "model": model, "rag": rag})
    return out


def write_outputs(results: List[Dict]):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    cols = [c for c in ["config", "model", "rag", "mcq_accuracy", "refusal_rate", "similarity",
                        "rouge_l", "groundedness", "n_mcq", "n_freeform", "n_refusal"]
            if any(c in r for r in results)]
    with open(RESULTS_DIR / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in cols})
    # markdown summary
    lines = ["# Benchmark results\n", "| " + " | ".join(cols) + " |",
             "|" + "|".join("---" for _ in cols) + "|"]
    for r in results:
        lines.append("| " + " | ".join(str(r.get(k, "")) for k in cols) + " |")
    (RESULTS_DIR / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"[eval] wrote {RESULTS_DIR/'results.csv'} and summary.md")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="qwen2.5-coder:1.5b")
    ap.add_argument("--custom", default="qwen-pentest-1.5b")
    ap.add_argument("--ft", default="qwen-pentest-ft-1.5b")
    ap.add_argument("--judge", default=None, help="optional judge model tag for groundedness")
    args = ap.parse_args()

    backend = OllamaBackend()
    embedder = None
    try:
        from sentence_transformers import SentenceTransformer
        embedder = SentenceTransformer("all-MiniLM-L6-v2")
    except Exception:
        print("[eval] sentence-transformers unavailable; similarity will be 0.0", file=sys.stderr)

    configs = default_configs(args.base, args.custom, args.ft)
    results = run(configs, backend, embedder=embedder, judge=args.judge)
    write_outputs(results)


if __name__ == "__main__":
    main()
