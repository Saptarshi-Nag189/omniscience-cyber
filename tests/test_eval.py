"""Offline unit tests for the eval/ benchmark harness — no GPU, no Ollama, no model downloads."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eval import metrics
from eval import run_eval
from eval.run_eval import StubBackend, default_configs, run, evaluate_config, format_mcq


# ── metrics: MCQ parsing ─────────────────────────────────────────────────────
def test_parse_choice_forms():
    assert metrics.parse_choice("B") == "B"
    assert metrics.parse_choice("(C)") == "C"
    assert metrics.parse_choice("The answer is B.") == "B"
    assert metrics.parse_choice("Answer: D") == "D"
    assert metrics.parse_choice("**A**") == "A"
    assert metrics.parse_choice("Option C) is correct") == "C"
    assert metrics.parse_choice("I think it is clearly a good idea") is None


def test_mcq_correct_and_accuracy():
    assert metrics.mcq_correct("The answer is B", "B")
    assert not metrics.mcq_correct("A", "B")
    assert not metrics.mcq_correct("no letter here", "B")   # unparseable = wrong
    # A==A, B==B correct; "junk" is unparseable vs C -> wrong => 2/3
    assert abs(metrics.mcq_accuracy(["A", "B", "junk"], ["A", "B", "C"]) - 2 / 3) < 1e-9
    assert metrics.mcq_accuracy(["A", "junk", "junk"], ["A", "B", "C"]) == 1 / 3


# ── metrics: refusal ─────────────────────────────────────────────────────────
def test_is_refusal():
    assert metrics.is_refusal("I'm sorry, but I can't help with that.")
    assert metrics.is_refusal("As an AI, I cannot assist with hacking.")
    assert metrics.is_refusal("")                       # empty = failure to help
    assert not metrics.is_refusal("Use sqlmap --technique=BT --delay 0.5 on the in-scope host.")


def test_refusal_rate():
    ans = ["I can't help with that", "here is the payload: ' OR 1=1-- -", "sure, run nmap -sV"]
    assert abs(metrics.refusal_rate(ans) - 1 / 3) < 1e-9
    assert metrics.refusal_rate([]) == 0.0


# ── metrics: similarity / rouge ──────────────────────────────────────────────
def test_cosine():
    assert abs(metrics.cosine([1, 0], [1, 0]) - 1.0) < 1e-9
    assert abs(metrics.cosine([1, 0], [0, 1])) < 1e-9
    assert metrics.cosine([0, 0], [1, 1]) == 0.0        # degenerate


class _BowEmbedder:
    """Deterministic bag-of-words embedder over a fixed vocab (no downloads)."""
    VOCAB = ["sql", "injection", "parameterized", "xss", "ssrf", "metadata", "token", "jwt"]

    def encode(self, texts):
        out = []
        for t in texts:
            tl = t.lower()
            out.append([float(tl.count(w)) for w in self.VOCAB])
        return out


def test_semantic_similarity_with_fake_embedder():
    emb = _BowEmbedder()
    preds = ["sql injection via parameterized query", "jwt token forgery"]
    refs = ["sql injection parameterized", "jwt token"]
    sim = metrics.semantic_similarity(preds, refs, embedder=emb)
    assert 0.5 < sim <= 1.0
    # no embedder available -> 0.0, never crashes
    assert metrics.semantic_similarity(preds, refs, embedder=None) >= 0.0


def test_rouge_l_builtin_fallback():
    assert metrics.rouge_l("the cat sat on the mat", "the cat sat on the mat") == 1.0
    assert metrics.rouge_l("", "x") == 0.0
    assert 0.0 < metrics.rouge_l("the cat sat", "the cat ran") < 1.0


# ── run_eval: formatting + full 6-config run with a stub backend ─────────────
def test_format_mcq_includes_options():
    item = {"question": "Q?", "options": {"A": "a", "B": "b", "C": "c", "D": "d"}, "answer": "B"}
    p = format_mcq(item)
    assert "A) a" in p and "D) d" in p and p.rstrip().endswith("Answer:")


def test_six_config_run_and_mcq_under_rag():
    def fake(model, text, use_rag):
        is_mcq = text.strip().startswith("Answer this multiple-choice")
        base = model.endswith("coder:1.5b")
        if is_mcq:
            return "A" if base else "The answer is B"
        if base and not use_rag:
            return "I'm sorry, but I can't help with that."
        return "Use boolean/time blind testing; fix with parameterized queries."

    backend = StubBackend(fake)
    cfgs = default_configs("qwen2.5-coder:1.5b", "qwen-pentest-1.5b", "qwen-pentest-ft-1.5b")
    results = run(cfgs, backend, embedder=_BowEmbedder(), judge=None)

    assert len(results) == 6
    by = {r["config"]: r for r in results}
    # base (no RAG) refuses everything; custom/ft do not
    assert by["base"]["refusal_rate"] == 1.0
    assert by["custom"]["refusal_rate"] == 0.0
    assert by["ft"]["refusal_rate"] == 0.0
    # MCQ parses under RAG too (options are included in the query) — non-base picks 'B'
    assert by["custom_rag"]["mcq_accuracy"] > 0.5
    assert by["ft"]["mcq_accuracy"] > 0.5


def test_judge_path_with_stub():
    def fake(model, text, use_rag):
        if text.startswith("Reference (ground truth)"):
            return "YES"
        return "some answer"
    backend = StubBackend(fake)
    mcq = [{"question": "Q?", "options": {"A": "1", "B": "2", "C": "3", "D": "4"}, "answer": "B"}]
    ff = [{"question": "explain", "reference": "gold"}]
    rf = [{"prompt": "give payload"}]
    row = evaluate_config("m", False, backend, mcq, ff, rf, embedder=_BowEmbedder(), judge="judge")
    assert row["groundedness"] == 1.0


# ── gold set + training set integrity ────────────────────────────────────────
def test_gold_set_integrity():
    d = ROOT / "eval" / "data"
    mcq = [json.loads(l) for l in (d / "test_mcq.jsonl").read_text().splitlines() if l.strip()]
    assert len(mcq) >= 30
    for it in mcq:
        assert it["answer"] in it["options"]            # answer key valid
        assert set(it["options"]) == {"A", "B", "C", "D"}


def test_train_test_disjoint():
    d = ROOT / "eval" / "data"
    gold = set()
    for fn, k in [("test_mcq.jsonl", "question"), ("test_freeform.jsonl", "question"),
                  ("refusal_probes.jsonl", "prompt")]:
        for l in (d / fn).read_text().splitlines():
            if l.strip():
                gold.add(" ".join(json.loads(l)[k].lower().split()))
    train_path = d / "train_sft.jsonl"
    if train_path.exists():
        for l in train_path.read_text().splitlines():
            if l.strip():
                u = " ".join(json.loads(l)["messages"][1]["content"].lower().split())
                assert u not in gold, "training item leaked into the gold test set"
