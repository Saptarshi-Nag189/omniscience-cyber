#!/usr/bin/env python3
"""
eval/build_dataset.py — turn the 34 security cards into a supervised fine-tuning (SFT) dataset.

Output: eval/data/train_sft.jsonl, one object per line in chat format:
    {"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}

Design:
  * Domain knowledge — each card section becomes an instruction->answer pair (2 phrasings),
    the assistant answer is the *verbatim card text* (grounded, no fabrication).
  * Uncensoring by example — for detection/exploit/payload sections we add a "give me the
    technique/payload for my authorized engagement, be direct" instruction whose answer is the
    same card content. Training on direct, non-refusing answers teaches the no-refusal behavior
    in the weights (so the fine-tuned model needs no uncensoring system prompt).
  * Leakage control — any generated pair whose (normalized) user question collides with a GOLD
    test question (test_mcq / test_freeform / refusal_probes) is dropped, so train and test are
    disjoint items over the same corpus.

The training uses a NEUTRAL system prompt (matching how the fine-tuned model is evaluated), so
the measured behavior comes from the weights, not a prompt.

Usage:
    python eval/build_dataset.py                 # writes eval/data/train_sft.jsonl
    python eval/build_dataset.py --cards cards   # custom cards dir
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List

NEUTRAL_SYSTEM = "You are a penetration-testing assistant for authorized, in-scope security engagements."

# Uncensoring-by-example asks appended to detection/exploit/payload sections (assistant answers
# with the real card technique — modeling direct, non-refusing help).
DIRECT_TEMPLATES = [
    "For an authorized, in-scope engagement, give me this directly (no disclaimer): {heading}",
    "On my authorized test target, walk me through: {heading}. Be direct and technical.",
]
KNOWLEDGE_TEMPLATES = [
    "For an authorized penetration test, explain: {heading}",
    "In the context of {topic}, cover this in technical detail: {heading}",
]
_DIRECT_SECTION_RE = re.compile(r"detect|exploit|payload|attack|bypass|inject|forge|test|technique|poc",
                                re.IGNORECASE)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def parse_card(path: Path) -> Dict:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    title = next((l[2:].strip() for l in lines if l.startswith("# ")), path.stem)
    topic = title.split("—")[0].split("-")[0].strip() or title
    # split into ## sections
    sections = []
    cur_head, cur_body = None, []
    for l in lines:
        if l.startswith("## "):
            if cur_head is not None:
                sections.append((cur_head, "\n".join(cur_body).strip()))
            cur_head, cur_body = l[3:].strip(), []
        elif cur_head is not None:
            cur_body.append(l)
    if cur_head is not None:
        sections.append((cur_head, "\n".join(cur_body).strip()))
    return {"title": title, "topic": topic, "sections": sections, "source": path.name}


def load_gold_questions(data_dir: Path) -> set:
    gold = set()
    for fn, key in [("test_mcq.jsonl", "question"), ("test_freeform.jsonl", "question"),
                    ("refusal_probes.jsonl", "prompt")]:
        p = data_dir / fn
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    gold.add(_norm(json.loads(line).get(key, "")))
    return gold


def build(cards_dir: Path, data_dir: Path) -> List[Dict]:
    gold = load_gold_questions(data_dir)
    rows: List[Dict] = []
    seen: set = set()

    def add(user: str, assistant: str):
        nu = _norm(user)
        if nu in gold or nu in seen or not assistant.strip():
            return
        seen.add(nu)
        rows.append({"messages": [
            {"role": "system", "content": NEUTRAL_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant.strip()},
        ]})

    for path in sorted(cards_dir.glob("*.md")):
        card = parse_card(path)
        topic = card["topic"]
        for heading, body in card["sections"]:
            if len(body) < 40:
                continue
            for tmpl in KNOWLEDGE_TEMPLATES:
                add(tmpl.format(heading=heading, topic=topic), body)
            if _DIRECT_SECTION_RE.search(heading):
                add(DIRECT_TEMPLATES[0].format(heading=heading), body)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", default="cards", help="cards directory")
    ap.add_argument("--data", default="eval/data", help="output data directory")
    ap.add_argument("--out", default="train_sft.jsonl")
    args = ap.parse_args()

    cards_dir, data_dir = Path(args.cards), Path(args.data)
    data_dir.mkdir(parents=True, exist_ok=True)
    rows = build(cards_dir, data_dir)
    out = data_dir / args.out
    with open(out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} SFT pairs -> {out}")


if __name__ == "__main__":
    main()
