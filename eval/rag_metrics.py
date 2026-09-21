"""
eval/rag_metrics.py — mathematical RAG-quality metrics (retrieval, chunking, faithfulness).

All deterministic and dependency-light (reuses the embedder RagCore already loads; falls back to
lexical overlap when no embedder is passed). Definitions follow standard IR / RAGAS formulations:

Retrieval quality (need a ground-truth relevant doc id per query):
  hit_at_k        1 if the relevant doc is in the top-k retrieved, else 0
  reciprocal_rank 1/rank of the first relevant doc (0 if absent)  -> MRR when averaged
  precision_at_k  relevant-in-topk / k
  recall_at_k     relevant-in-topk / total-relevant
  ndcg_at_k       normalized discounted cumulative gain (graded by rank)

Chunking quality:
  context_answer_recall   token recall of the gold answer inside the retrieved context
                          (how much of the answer the retrieved chunks actually contain)
  chunk_cohesion          mean intra-chunk similarity minus mean inter-chunk similarity
                          (well-formed chunks are internally cohesive, externally distinct)

Answer quality / hallucination:
  faithfulness    mean over answer sentences of the max cosine to any context sentence, blended
                  with n-gram support in the context (the RAGAS "answer is grounded in context"
                  idea, computed without an LLM)
  answer_relevancy cosine(question, answer)
"""
from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Sequence

from eval.metrics import cosine, _lcs_len  # reuse

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_WORD = re.compile(r"[a-z0-9]{2,}")


def _sentences(text: str) -> List[str]:
    return [s.strip() for s in _SENT_SPLIT.split(text or "") if s.strip()]


def _tokens(text: str) -> List[str]:
    return _WORD.findall((text or "").lower())


# ─────────────────────────────────────────────────────────────────────────────
# Retrieval / ranking metrics
#   retrieved: ranked list of doc ids (best first); relevant: the ground-truth id(s)
# ─────────────────────────────────────────────────────────────────────────────
def _relset(relevant) -> set:
    return {relevant} if isinstance(relevant, str) else set(relevant or [])


def hit_at_k(retrieved: Sequence[str], relevant, k: int) -> float:
    rel = _relset(relevant)
    return 1.0 if any(d in rel for d in retrieved[:k]) else 0.0


def reciprocal_rank(retrieved: Sequence[str], relevant) -> float:
    rel = _relset(relevant)
    for i, d in enumerate(retrieved, 1):
        if d in rel:
            return 1.0 / i
    return 0.0


def precision_at_k(retrieved: Sequence[str], relevant, k: int) -> float:
    if k <= 0:
        return 0.0
    rel = _relset(relevant)
    return sum(1 for d in retrieved[:k] if d in rel) / k


def recall_at_k(retrieved: Sequence[str], relevant, k: int) -> float:
    rel = _relset(relevant)
    if not rel:
        return 0.0
    return sum(1 for d in retrieved[:k] if d in rel) / len(rel)


def ndcg_at_k(retrieved: Sequence[str], relevant, k: int) -> float:
    rel = _relset(relevant)
    if not rel:
        return 0.0
    dcg = sum((1.0 / math.log2(i + 1)) for i, d in enumerate(retrieved[:k], 1) if d in rel)
    ideal = sum(1.0 / math.log2(i + 1) for i in range(1, min(len(rel), k) + 1))
    return dcg / ideal if ideal else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Chunking quality
# ─────────────────────────────────────────────────────────────────────────────
def context_answer_recall(reference: str, context: str) -> float:
    """Fraction of the gold answer's content tokens that appear in the retrieved context.
    High = the retrieved chunk actually contains the answer (good chunk boundaries + retrieval)."""
    ref = _tokens(reference)
    if not ref:
        return 0.0
    ctx = set(_tokens(context))
    return sum(1 for t in ref if t in ctx) / len(ref)


def chunk_cohesion(chunks_sentences: List[List[str]], embedder=None, max_pairs: int = 200) -> Dict[str, float]:
    """
    Given each chunk as a list of its sentences, return intra/inter mean similarity and the
    cohesion gap (intra - inter). A larger gap => chunks are internally coherent and mutually
    distinct (good chunking). Uses embeddings if provided, else token-Jaccard.
    """
    def sim(a: str, b: str) -> float:
        if embedder is not None:
            va, vb = embedder.encode([a, b])
            va = va.tolist() if hasattr(va, "tolist") else list(va)
            vb = vb.tolist() if hasattr(vb, "tolist") else list(vb)
            return cosine(va, vb)
        ta, tb = set(_tokens(a)), set(_tokens(b))
        return len(ta & tb) / len(ta | tb) if (ta | tb) else 0.0

    intra, inter = [], []
    for sents in chunks_sentences:
        for i in range(len(sents)):
            for j in range(i + 1, len(sents)):
                intra.append(sim(sents[i], sents[j]))
                if len(intra) >= max_pairs:
                    break
    # inter: pair the first sentence of each chunk with the first of the next
    firsts = [s[0] for s in chunks_sentences if s]
    for i in range(len(firsts)):
        for j in range(i + 1, len(firsts)):
            inter.append(sim(firsts[i], firsts[j]))
            if len(inter) >= max_pairs:
                break
    mi = sum(intra) / len(intra) if intra else 0.0
    mo = sum(inter) / len(inter) if inter else 0.0
    return {"intra": round(mi, 4), "inter": round(mo, 4), "cohesion_gap": round(mi - mo, 4)}


def chunk_size_stats(texts: Sequence[str]) -> Dict[str, float]:
    sizes = [len(_tokens(t)) for t in texts]
    if not sizes:
        return {"count": 0, "mean_tokens": 0.0, "min_tokens": 0, "max_tokens": 0}
    return {"count": len(sizes), "mean_tokens": round(sum(sizes) / len(sizes), 1),
            "min_tokens": min(sizes), "max_tokens": max(sizes)}


# ─────────────────────────────────────────────────────────────────────────────
# Answer quality / hallucination (deterministic, no LLM)
# ─────────────────────────────────────────────────────────────────────────────
def _embed_cos(a: str, b: str, embedder) -> float:
    if embedder is None:
        ta, tb = set(_tokens(a)), set(_tokens(b))
        return len(ta & tb) / len(ta | tb) if (ta | tb) else 0.0
    va, vb = embedder.encode([a, b])
    va = va.tolist() if hasattr(va, "tolist") else list(va)
    vb = vb.tolist() if hasattr(vb, "tolist") else list(vb)
    return cosine(va, vb)


def faithfulness(answer: str, context: str, embedder=None, support_threshold: float = 0.5) -> float:
    """
    Hallucination metric: fraction of answer sentences that are SUPPORTED by the retrieved
    context. A sentence is supported if its max cosine to any context sentence >= threshold OR
    most of its content tokens appear in the context. 1.0 = fully grounded, low = hallucinated.
    """
    ans_sents = _sentences(answer)
    if not ans_sents:
        return 0.0
    ctx_sents = _sentences(context) or [context or ""]
    supported = 0
    for s in ans_sents:
        max_cos = max((_embed_cos(s, c, embedder) for c in ctx_sents), default=0.0)
        toks = _tokens(s)
        ctx_tok = set(_tokens(context))
        ngram_support = (sum(1 for t in toks if t in ctx_tok) / len(toks)) if toks else 0.0
        if max_cos >= support_threshold or ngram_support >= 0.6:
            supported += 1
    return supported / len(ans_sents)


def answer_relevancy(question: str, answer: str, embedder=None) -> float:
    """Cosine similarity between the question and the answer (is the answer on-topic?)."""
    if not question or not answer:
        return 0.0
    return max(0.0, _embed_cos(question, answer, embedder))


def mean(xs: Sequence[float]) -> float:
    xs = list(xs)
    return round(sum(xs) / len(xs), 4) if xs else 0.0
