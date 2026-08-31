#!/usr/bin/env python3
"""
eval/plots.py — render grouped bar charts from eval/results/results.csv for the writeup.

Produces (in eval/results/):
  mcq_accuracy.png, refusal_rate.png, similarity.png  — one grouped bar chart per metric,
  x = model variant (base / custom / ft), bars = RAG off vs on.

Usage:  python eval/plots.py
"""
from __future__ import annotations

import csv
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"

# metric -> (nice title, higher_is_better)
METRICS = {
    "mcq_accuracy": ("MCQ accuracy (higher = better)", True),
    "refusal_rate": ("Refusal rate (lower = better)", False),
    "similarity": ("Answer similarity to gold (higher = better)", True),
    "rouge_l": ("ROUGE-L vs gold (higher = better)", True),
    "groundedness": ("Groundedness / faithfulness (higher = better)", True),
}
VARIANT_ORDER = ["base", "custom", "ft"]
VARIANT_LABEL = {"base": "base\n(raw)", "custom": "custom\n(modelfile)", "ft": "fine-tuned\n(QLoRA)"}


def load_results(path: Path):
    rows = list(csv.DictReader(open(path)))
    # index by (variant, rag)
    idx = {}
    for r in rows:
        variant = r["config"].replace("_rag", "")
        rag = str(r["rag"]).lower() in ("true", "1", "yes")
        idx[(variant, rag)] = r
    return idx


def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    csv_path = RESULTS / "results.csv"
    if not csv_path.exists():
        raise SystemExit(f"no results at {csv_path} — run eval/run_eval.py first")
    idx = load_results(csv_path)
    present = [m for m in METRICS if any(m in r and r[m] != "" for r in idx.values())]

    for metric in present:
        title, _ = METRICS[metric]
        off = [_get(idx, v, False, metric) for v in VARIANT_ORDER]
        on = [_get(idx, v, True, metric) for v in VARIANT_ORDER]
        x = range(len(VARIANT_ORDER))
        w = 0.38
        fig, ax = plt.subplots(figsize=(7, 4.2))
        ax.bar([i - w / 2 for i in x], off, w, label="RAG off", color="#7b8794")
        ax.bar([i + w / 2 for i in x], on, w, label="RAG on", color="#2f80ed")
        ax.set_xticks(list(x))
        ax.set_xticklabels([VARIANT_LABEL[v] for v in VARIANT_ORDER])
        ax.set_title(title)
        ax.set_ylabel(metric)
        ax.legend()
        for i in x:
            for val, dx in ((off[i], -w / 2), (on[i], w / 2)):
                ax.text(i + dx, val, f"{val:.2f}", ha="center", va="bottom", fontsize=8)
        fig.tight_layout()
        out = RESULTS / f"{metric}.png"
        fig.savefig(out, dpi=130)
        plt.close(fig)
        print(f"[plots] wrote {out}")


def _get(idx, variant, rag, metric):
    r = idx.get((variant, rag))
    if not r or r.get(metric, "") == "":
        return 0.0
    try:
        return float(r[metric])
    except ValueError:
        return 0.0


if __name__ == "__main__":
    main()
