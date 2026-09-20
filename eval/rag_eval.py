#!/usr/bin/env python3
"""
eval/rag_eval.py — measure RAG quality (retrieval, chunking, faithfulness) on the gold set.

For each gold question it retrieves cards and generates a RAG answer, then scores:
  retrieval:  Hit@k, MRR, nDCG@k, Precision@k, Recall@k  (vs the gold `card` label)
  chunking:   context_answer_recall, and corpus-level chunk_cohesion + size stats
  answer:     faithfulness (hallucination), answer_relevancy, answer_correctness (similarity)

Writes eval/results/rag_metrics.json (aggregate + per-topic). Deterministic; no LLM judge.

Backends are pluggable so this is unit-testable offline:
  - RagBackend (real): wraps rag_core.RagCore (.retrieve + .ask).
  - a stub with retrieve_fn/answer_fn for tests.

Usage (needs Ollama + an ingested card DB):
    python eval/rag_eval.py --model qwen-pentest-1.5b --k 4
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rag"))

from eval import rag_metrics as M  # noqa: E402
from eval import metrics as BASE   # noqa: E402

DATA = ROOT / "eval" / "data"
RESULTS = ROOT / "eval" / "results"


class RagBackend:
    """Real backend over rag_core.RagCore."""

    def __init__(self, model: str, k: int = 4):
        from rag_core import RagCore
        self.rag = RagCore()
        self.model = model
        self.k = k

    def retrieve(self, question: str) -> List[str]:
        hits = self.rag.retrieve(question)
        return [h.get("source", "") for h in hits][: self.k]

    def answer(self, question: str) -> Dict[str, str]:
        r = self.rag.ask(question, model=self.model, think=False)
        return {"answer": r.get("answer", ""), "context": r.get("context", "")}

    def embedder(self):
        try:
            return self.rag._embedder()
        except Exception:
            return None


def load_jsonl(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def evaluate(backend, k: int = 4, embedder=None) -> Dict:
    mcq = load_jsonl(DATA / "test_mcq.jsonl")
    ff = load_jsonl(DATA / "test_freeform.jsonl")
    items = [{"q": it["question"], "card": it.get("card"), "ref": None} for it in mcq]
    items += [{"q": it["question"], "card": it.get("card"), "ref": it.get("reference")} for it in ff]

    per = {"hit": [], "mrr": [], "ndcg": [], "precision": [], "recall": [],
           "ctx_answer_recall": [], "faithfulness": [], "answer_relevancy": [], "similarity": []}
    by_topic: Dict[str, List[float]] = {}

    for it in items:
        retrieved = backend.retrieve(it["q"])
        card = it["card"]
        per["hit"].append(M.hit_at_k(retrieved, card, k))
        per["mrr"].append(M.reciprocal_rank(retrieved, card))
        per["ndcg"].append(M.ndcg_at_k(retrieved, card, k))
        per["precision"].append(M.precision_at_k(retrieved, card, k))
        per["recall"].append(M.recall_at_k(retrieved, card, k))
        by_topic.setdefault(card or "?", []).append(M.hit_at_k(retrieved, card, k))

        out = backend.answer(it["q"])
        ans, ctx = out["answer"], out["context"]
        per["faithfulness"].append(M.faithfulness(ans, ctx, embedder=embedder))
        per["answer_relevancy"].append(M.answer_relevancy(it["q"], ans, embedder=embedder))
        if it["ref"]:
            per["ctx_answer_recall"].append(M.context_answer_recall(it["ref"], ctx))
            per["similarity"].append(BASE.semantic_similarity([ans], [it["ref"]], embedder=embedder))

    # corpus-level chunking quality over the cards themselves
    cohesion, sizes = _corpus_chunk_quality(embedder)

    agg = {name: M.mean(vals) for name, vals in per.items()}
    return {
        "k": k,
        "n_queries": len(items),
        "retrieval": {kk: agg[kk] for kk in ("hit", "mrr", "ndcg", "precision", "recall")},
        "chunking": {"context_answer_recall": agg["ctx_answer_recall"],
                     "cohesion": cohesion, "size": sizes},
        "answer": {"faithfulness": agg["faithfulness"],
                   "answer_relevancy": agg["answer_relevancy"],
                   "similarity": agg["similarity"]},
        "hit_by_card": {c: M.mean(v) for c, v in sorted(by_topic.items())},
    }


def _corpus_chunk_quality(embedder):
    cards = sorted((ROOT / "cards").glob("*.md"))
    texts, chunk_sents = [], []
    import re
    for c in cards:
        t = c.read_text(encoding="utf-8", errors="ignore")
        texts.append(t)
        sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", t) if len(s.strip()) > 20]
        if sents:
            chunk_sents.append(sents[:8])   # cap per card for speed
    cohesion = M.chunk_cohesion(chunk_sents, embedder=embedder)
    sizes = M.chunk_size_stats(texts)
    return cohesion, sizes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen-pentest-1.5b")
    ap.add_argument("--k", type=int, default=4)
    args = ap.parse_args()

    backend = RagBackend(args.model, k=args.k)
    result = evaluate(backend, k=args.k, embedder=backend.embedder())
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / "rag_metrics.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"[rag-eval] wrote {out}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
