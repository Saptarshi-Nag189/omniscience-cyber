"""
eval/project_stats.py — collect project-specific stats for the dashboard.

Pure repository scan (no GPU/Ollama/network). These are the "other relevant stats specific to this
project" shown alongside the benchmark and RAG-quality numbers.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for l in path.read_text(encoding="utf-8").splitlines() if l.strip())
    except Exception:
        return 0


def collect(root: Path = ROOT) -> Dict:
    cards = sorted((root / "cards").glob("*.md"))
    modelfiles = sorted((root / "modelfiles").glob("*.Modelfile"))
    templates = sorted((root / "templates").glob("*.yaml"))
    data = root / "eval" / "data"

    # card topics (from filenames like 03_sqli.md -> "sqli")
    topics = [re.sub(r"^\d+_", "", c.stem) for c in cards]

    # keyword coverage: cards that declare a *Keywords:* line
    kw_cards = 0
    total_keywords = 0
    for c in cards:
        txt = c.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"\*Keywords:\*(.+)", txt)
        if m:
            kw_cards += 1
            total_keywords += len([k for k in m.group(1).split(",") if k.strip()])

    # forbidden RoE categories from the example config
    forbid = []
    cfg = root / "config.example.yaml"
    if cfg.exists():
        c = cfg.read_text(encoding="utf-8")
        block = re.search(r"forbid:\s*((?:\s*-\s*\w+.*\n)+)", c)
        if block:
            forbid = re.findall(r"-\s*([a-z_]+)", block.group(1))

    stats = {
        "cards": {
            "count": len(cards),
            "topics": topics,
            "with_keywords": kw_cards,
            "total_keywords": total_keywords,
        },
        "models": {
            "count": len(modelfiles),
            "tags": [m.stem for m in modelfiles],
        },
        "orchestrator": {
            "campaign_templates": len(templates),
            "template_names": [t.stem for t in templates],
            "rag_modules": len(list((root / "rag").glob("*.py"))),
        },
        "guardrails": {
            "forbidden_categories": forbid,
            "count": len(forbid),
        },
        "datasets": {
            "sft_pairs": _count_lines(data / "train_sft.jsonl"),
            "gold_mcq": _count_lines(data / "test_mcq.jsonl"),
            "gold_freeform": _count_lines(data / "test_freeform.jsonl"),
            "refusal_probes": _count_lines(data / "refusal_probes.jsonl"),
        },
        "tests": {
            "test_files": len(list((root / "tests").glob("test_*.py"))),
        },
    }
    return stats


def main():
    out = ROOT / "eval" / "results" / "project_stats.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    stats = collect()
    out.write_text(json.dumps(stats, indent=2))
    print(f"[stats] wrote {out}")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
