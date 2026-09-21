# Benchmark results — small-model specialization for authorized pentesting

**Base model:** `Qwen2.5-Coder-1.5B` · **Hardware:** RTX 4050 (6GB VRAM, 8GB RAM) ·
**Fine-tune:** QLoRA (4-bit, LoRA r=16) on 318 SFT pairs distilled from 34 security cards ·
**Test set:** 36 MCQ + 10 free-form + 12 refusal probes, hand-authored and held out.

> This file is the resume-facing writeup. Fill the table and paste the charts after running
> `python eval/run_eval.py && python eval/plots.py` on the GPU box. Numbers below are **placeholders
> until you run it** — do not cite them until the run completes.

## Setup

Three variants of the *same* base model, each evaluated with retrieval (RAG) off and on:

- **base** — raw `qwen2.5-coder:1.5b`.
- **custom** — `qwen-pentest-1.5b`: uncensored via a system prompt only (no weight change).
- **ft** — `qwen-pentest-ft-1.5b`: QLoRA fine-tuned so domain knowledge *and* no-refusal behavior
  live in the weights; evaluated with a **neutral** system prompt.

## Results (fill in)

| Config | RAG | MCQ acc ↑ | Refusal ↓ | Similarity ↑ | ROUGE-L ↑ |
|---|---|---|---|---|---|
| base | off | _ | _ | _ | _ |
| base | on | _ | _ | _ | _ |
| custom | off | _ | _ | _ | _ |
| custom | on | _ | _ | _ | _ |
| ft | off | _ | _ | _ | _ |
| ft | on | _ | _ | _ | _ |

![MCQ accuracy](results/mcq_accuracy.png)
![Refusal rate](results/refusal_rate.png)
![Similarity](results/similarity.png)

## What to look for (the story)

- **Refusal rate:** base (raw) refuses authorized-pentest asks; both custom (prompt) and ft
  (weights) should drop it toward 0 — two different ways to "uncensor," quantified side by side.
- **MCQ accuracy / similarity:** RAG lifts every variant (retrieval supplies the exact card);
  fine-tuning should lift the **no-RAG** column most (knowledge internalized into weights).
- **RAG lift** = (on − off) per metric — shows retrieval and fine-tuning as complementary.

## Method notes (for credibility)

- Deterministic decoding (temperature 0). Metrics: MCQ exact-letter match; refusal via regex;
  similarity via `all-MiniLM-L6-v2` cosine; ROUGE-L; optional LLM-judge groundedness.
- Train/test are **disjoint items** over the same 34-card corpus (gold questions are excluded from
  the generated SFT set), so gains reflect learned knowledge/behavior, not memorized test items.
- Everything is local and offline; no data leaves the machine.
