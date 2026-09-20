#!/usr/bin/env python3
"""
eval/dashboard.py — render a single self-contained, offline HTML dashboard.

Aggregates three inputs (any may be missing — sections degrade gracefully):
  eval/results/project_stats.json   project-specific stats (cards, models, guardrails, datasets)
  eval/results/rag_metrics.json     RAG quality (retrieval / chunking / faithfulness)
  eval/results/results.csv          6-config model benchmark

Output: eval/results/dashboard.html — inline CSS + inline SVG charts, no server, no CDN, works
offline in any browser and adapts to light/dark.

Usage:
    python eval/dashboard.py                 # from whatever real results exist
    python eval/dashboard.py --sample        # fill representative SAMPLE numbers for a preview
"""
from __future__ import annotations

import argparse
import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "eval" / "results"


# ─────────────────────────────────────────────────────────────────────────────
# Inline SVG bar chart (no JS, no CDN)
# ─────────────────────────────────────────────────────────────────────────────
def svg_bars(labels: List[str], values: List[float], maxv: float = 1.0,
             good_high: bool = True, unit: str = "") -> str:
    if not values:
        return "<p class='muted'>no data</p>"
    W, rowh, pad, lblw = 460, 26, 6, 150
    H = rowh * len(values) + pad
    rows = []
    for i, (lab, v) in enumerate(zip(labels, values)):
        y = i * rowh + pad
        frac = 0.0 if maxv == 0 else max(0.0, min(1.0, v / maxv))
        barw = int((W - lblw - 60) * frac)
        # color: green when the value is "good", amber mid, red bad
        score = frac if good_high else 1 - frac
        color = "#2e7d32" if score >= 0.66 else ("#f9a825" if score >= 0.33 else "#c62828")
        rows.append(
            f'<text x="0" y="{y+16}" class="bl">{html.escape(lab)}</text>'
            f'<rect x="{lblw}" y="{y+4}" width="{W-lblw-60}" height="16" class="bg"/>'
            f'<rect x="{lblw}" y="{y+4}" width="{barw}" height="16" fill="{color}"/>'
            f'<text x="{W-52}" y="{y+16}" class="vl">{v:.3f}{unit}</text>')
    return (f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" class="chart">'
            + "".join(rows) + "</svg>")


def tile(label: str, value, sub: str = "") -> str:
    sub_html = f'<div class="tsub">{html.escape(sub)}</div>' if sub else ""
    return (f'<div class="tile"><div class="tval">{html.escape(str(value))}</div>'
            f'<div class="tlab">{html.escape(label)}</div>{sub_html}</div>')


# ─────────────────────────────────────────────────────────────────────────────
# Load inputs
# ─────────────────────────────────────────────────────────────────────────────
def _load_json(p: Path) -> Optional[dict]:
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _load_csv(p: Path) -> List[dict]:
    try:
        return list(csv.DictReader(open(p)))
    except Exception:
        return []


SAMPLE_RESULTS = [
    {"config": "base", "rag": "False", "mcq_accuracy": "0.31", "refusal_rate": "0.75", "similarity": "0.34", "rouge_l": "0.12"},
    {"config": "base_rag", "rag": "True", "mcq_accuracy": "0.58", "refusal_rate": "0.17", "similarity": "0.55", "rouge_l": "0.29"},
    {"config": "custom", "rag": "False", "mcq_accuracy": "0.44", "refusal_rate": "0.00", "similarity": "0.41", "rouge_l": "0.18"},
    {"config": "custom_rag", "rag": "True", "mcq_accuracy": "0.69", "refusal_rate": "0.00", "similarity": "0.63", "rouge_l": "0.34"},
    {"config": "ft", "rag": "False", "mcq_accuracy": "0.61", "refusal_rate": "0.00", "similarity": "0.52", "rouge_l": "0.27"},
    {"config": "ft_rag", "rag": "True", "mcq_accuracy": "0.75", "refusal_rate": "0.00", "similarity": "0.68", "rouge_l": "0.38"},
]
SAMPLE_RAG = {
    "k": 4, "n_queries": 46,
    "retrieval": {"hit": 0.93, "mrr": 0.86, "ndcg": 0.88, "precision": 0.27, "recall": 0.93},
    "chunking": {"context_answer_recall": 0.71,
                 "cohesion": {"intra": 0.42, "inter": 0.14, "cohesion_gap": 0.28},
                 "size": {"count": 34, "mean_tokens": 487, "min_tokens": 355, "max_tokens": 589}},
    "answer": {"faithfulness": 0.82, "answer_relevancy": 0.79, "similarity": 0.64},
}


# ─────────────────────────────────────────────────────────────────────────────
# Render
# ─────────────────────────────────────────────────────────────────────────────
def render(stats: Optional[dict], rag: Optional[dict], results: List[dict],
           sample: bool) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    banner = ('<div class="banner">SAMPLE / illustrative numbers — run '
              '<code>make rag-eval</code> and <code>make eval</code> for real results.</div>'
              if sample else "")

    # ── project stat tiles ──
    tiles = ""
    if stats:
        c, m = stats.get("cards", {}), stats.get("models", {})
        o, g = stats.get("orchestrator", {}), stats.get("guardrails", {})
        d = stats.get("datasets", {})
        tiles = "".join([
            tile("security cards", c.get("count", "?"), f'{c.get("total_keywords","?")} keywords'),
            tile("uncensored models", m.get("count", "?"), "modelfiles"),
            tile("campaign templates", o.get("campaign_templates", "?"), "DAG recon flows"),
            tile("RoE forbidden classes", g.get("count", "?"),
                 ", ".join(g.get("forbidden_categories", []))[:40]),
            tile("SFT training pairs", d.get("sft_pairs", "?"), "distilled from cards"),
            tile("gold test items",
                 d.get("gold_mcq", 0) + d.get("gold_freeform", 0) + d.get("refusal_probes", 0),
                 f'{d.get("gold_mcq",0)} MCQ · {d.get("gold_freeform",0)} free · {d.get("refusal_probes",0)} refusal'),
        ])

    # ── RAG quality ──
    rag_html = "<p class='muted'>No rag_metrics.json yet — run <code>make rag-eval</code>.</p>"
    if rag:
        r = rag.get("retrieval", {})
        ch = rag.get("chunking", {})
        an = rag.get("answer", {})
        coh = ch.get("cohesion", {})
        sz = ch.get("size", {})
        retr_chart = svg_bars(
            ["Hit@k", "MRR", "nDCG@k", "Precision@k", "Recall@k"],
            [r.get("hit", 0), r.get("mrr", 0), r.get("ndcg", 0), r.get("precision", 0), r.get("recall", 0)])
        ans_chart = svg_bars(
            ["Faithfulness (¬hallucination)", "Answer relevancy", "Answer similarity",
             "Context→answer recall"],
            [an.get("faithfulness", 0), an.get("answer_relevancy", 0), an.get("similarity", 0),
             ch.get("context_answer_recall", 0)])
        rag_html = f"""
        <div class="grid2">
          <div class="panel"><h3>Retrieval quality (k={rag.get('k','?')}, n={rag.get('n_queries','?')})</h3>{retr_chart}</div>
          <div class="panel"><h3>Answer quality &amp; hallucination</h3>{ans_chart}</div>
        </div>
        <div class="grid3">
          {tile("chunk cohesion gap", coh.get("cohesion_gap","?"), f'intra {coh.get("intra","?")} − inter {coh.get("inter","?")}')}
          {tile("mean chunk size", f'{sz.get("mean_tokens","?")} tok', f'{sz.get("min_tokens","?")}–{sz.get("max_tokens","?")} over {sz.get("count","?")} cards')}
          {tile("context→answer recall", an.get("similarity","?") if False else ch.get("context_answer_recall","?"), "answer present in retrieved chunk")}
        </div>"""

    # ── model benchmark ──
    bench_html = "<p class='muted'>No results.csv yet — run <code>make eval</code>.</p>"
    if results:
        cols = [c for c in ["config", "rag", "mcq_accuracy", "refusal_rate", "similarity", "rouge_l"]
                if c in results[0]]
        head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
        body = ""
        for row in results:
            body += "<tr>" + "".join(f"<td>{html.escape(str(row.get(c,'')))}</td>" for c in cols) + "</tr>"
        labels = [r["config"] for r in results]
        mcq = svg_bars(labels, [_f(r.get("mcq_accuracy")) for r in results])
        refu = svg_bars(labels, [_f(r.get("refusal_rate")) for r in results], good_high=False)
        bench_html = f"""
        <table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>
        <div class="grid2">
          <div class="panel"><h3>MCQ accuracy (higher = better)</h3>{mcq}</div>
          <div class="panel"><h3>Refusal rate (lower = better)</h3>{refu}</div>
        </div>"""

    return _PAGE.format(now=now, banner=banner, tiles=tiles or "<p class='muted'>no stats</p>",
                        rag=rag_html, bench=bench_html)


def _f(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>omniscience-cyber — evaluation dashboard</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#1a1f2b;--muted:#6b7280;--line:#e5e7eb;--accent:#2f80ed;--barbg:#eceff3}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f1420;--card:#1a2130;--fg:#e6e9ef;--muted:#9aa4b2;--line:#2a3345;--accent:#4c9aff;--barbg:#243040}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1000px;margin:0 auto;padding:24px 16px 64px}}
h1{{font-size:22px;margin:0 0 2px}}h2{{font-size:16px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}}
h3{{font-size:13px;margin:0 0 10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.03em}}
.sub{{color:var(--muted);margin:0 0 8px}}
.banner{{background:#fff3cd;color:#7a5c00;border:1px solid #ffe08a;border-radius:8px;padding:8px 12px;margin:12px 0;font-size:13px}}
@media(prefers-color-scheme:dark){{.banner{{background:#2a2410;color:#e8cf7a;border-color:#4a3e12}}}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.tval{{font-size:26px;font-weight:700;color:var(--accent)}}
.tlab{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}}
.tsub{{font-size:11px;color:var(--muted);margin-top:4px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px}}
.grid3{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px}}
@media(max-width:720px){{.grid2,.grid3{{grid-template-columns:1fr}}}}
.panel{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line)}}th{{color:var(--muted);font-weight:600}}
tr:last-child td{{border-bottom:none}}
.chart .bl{{font-size:11px;fill:var(--fg)}}.chart .vl{{font-size:11px;fill:var(--muted);text-anchor:end}}.chart .bg{{fill:var(--barbg)}}
.muted{{color:var(--muted)}}code{{background:var(--barbg);padding:1px 5px;border-radius:4px;font-size:12px}}
footer{{margin-top:40px;color:var(--muted);font-size:12px}}
</style></head><body><div class="wrap">
<h1>omniscience-cyber — evaluation dashboard</h1>
<p class="sub">Offline RAG + fine-tuning quality report · generated {now}</p>
{banner}
<h2>Project at a glance</h2>
<div class="tiles">{tiles}</div>
<h2>RAG quality — retrieval, chunking &amp; hallucination</h2>
{rag}
<h2>Model benchmark — 6 configurations</h2>
{bench}
<footer>All metrics computed locally and offline. Retrieval: Hit@k / MRR / nDCG / Precision / Recall
vs the gold relevant-card label. Faithfulness = fraction of answer sentences grounded in the
retrieved context (deterministic embedding + n-gram support). Chunk cohesion = intra − inter
sentence similarity.</footer>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", action="store_true", help="fill representative sample numbers")
    ap.add_argument("--out", default=str(RESULTS / "dashboard.html"))
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    stats = _load_json(RESULTS / "project_stats.json")
    if stats is None:
        from eval.project_stats import collect
        stats = collect()
    rag = _load_json(RESULTS / "rag_metrics.json")
    results = _load_csv(RESULTS / "results.csv")

    sample = args.sample
    if sample:
        rag = rag or SAMPLE_RAG
        results = results or SAMPLE_RESULTS
    if not rag and not results and not args.sample:
        # nothing to show beyond stats — still emit the page (sections say "run make ...")
        pass

    html_str = render(stats, rag, results, sample=sample and (rag is SAMPLE_RAG or results is SAMPLE_RESULTS))
    Path(args.out).write_text(html_str, encoding="utf-8")
    print(f"[dashboard] wrote {args.out}")


if __name__ == "__main__":
    main()
