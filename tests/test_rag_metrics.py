"""Offline unit tests for eval/rag_metrics.py — pure math, no GPU/Ollama/embedding downloads."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval import rag_metrics as M


# ── retrieval / ranking ──────────────────────────────────────────────────────
def test_hit_and_reciprocal_rank():
    ret = ["b.md", "a.md", "c.md"]
    assert M.hit_at_k(ret, "a.md", 3) == 1.0
    assert M.hit_at_k(ret, "a.md", 1) == 0.0          # a.md not in top-1
    assert M.reciprocal_rank(ret, "a.md") == 0.5      # rank 2
    assert M.reciprocal_rank(ret, "zzz.md") == 0.0


def test_precision_recall_at_k():
    ret = ["a.md", "x.md", "y.md", "z.md"]
    assert M.precision_at_k(ret, "a.md", 4) == 0.25
    assert M.recall_at_k(ret, "a.md", 4) == 1.0
    assert M.recall_at_k(ret, {"a.md", "b.md"}, 4) == 0.5


def test_ndcg_rewards_higher_rank():
    first = M.ndcg_at_k(["a.md", "x.md", "y.md"], "a.md", 3)
    last = M.ndcg_at_k(["x.md", "y.md", "a.md"], "a.md", 3)
    assert first == 1.0
    assert 0.0 < last < first                          # same doc, lower rank -> lower nDCG


# ── chunking ─────────────────────────────────────────────────────────────────
def test_context_answer_recall():
    ref = "use parameterized queries"
    assert M.context_answer_recall(ref, "always use parameterized queries everywhere") == 1.0
    assert M.context_answer_recall(ref, "unrelated text about cats") == 0.0
    assert M.context_answer_recall("", "anything") == 0.0


def test_chunk_cohesion_gap_positive_when_chunks_are_distinct():
    # two internally-repetitive, mutually-distinct chunks -> intra > inter -> positive gap
    chunks = [
        ["sql injection payload here", "sql injection detection method", "sql injection cvss score"],
        ["oauth redirect uri attack", "oauth redirect uri bypass", "oauth redirect uri fix"],
    ]
    out = M.chunk_cohesion(chunks, embedder=None)       # token-Jaccard fallback
    assert out["intra"] > out["inter"]
    assert out["cohesion_gap"] > 0


def test_chunk_size_stats():
    # tokens are >=2 chars (single letters are not counted)
    s = M.chunk_size_stats(["one two three", "aa bb", "ww xx yy zz qq"])
    assert s["count"] == 3 and s["min_tokens"] == 2 and s["max_tokens"] == 5


# ── answer quality / hallucination ───────────────────────────────────────────
class _Bow:
    V = ["sql", "injection", "parameterized", "queries", "cats", "moon", "scope", "owner"]

    def encode(self, texts):
        return [[float(t.lower().count(w)) for w in self.V] for t in texts]


def test_faithfulness_grounded_vs_hallucinated():
    ctx = "SQL injection is fixed with parameterized queries. Defer scope to the owner."
    grounded = "Use parameterized queries. Defer scope to the owner."
    hallucinated = "The moon is made of cheese and cats rule everything."
    assert M.faithfulness(grounded, ctx, embedder=_Bow()) >= 0.5
    assert M.faithfulness(hallucinated, ctx, embedder=_Bow()) < 0.5
    assert M.faithfulness("", ctx, embedder=_Bow()) == 0.0


def test_answer_relevancy():
    q = "how do I fix sql injection"
    on = "sql injection is fixed with parameterized queries"
    off = "the moon and cats"
    assert M.answer_relevancy(q, on, embedder=_Bow()) > M.answer_relevancy(q, off, embedder=_Bow())


def test_mean_helper():
    assert M.mean([1.0, 0.0]) == 0.5
    assert M.mean([]) == 0.0
