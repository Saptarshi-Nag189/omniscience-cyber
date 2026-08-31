# Fine-tuning + benchmark harness (`eval/`)

Quantifies three ways to specialize **one small base model** (`Qwen2.5-Coder-1.5B`) for the
authorized-pentest domain, each measured **with and without RAG** — a **3 × 2 = 6** matrix.

| Variant | Ollama model | Uncensoring comes from | Domain knowledge from |
|---|---|---|---|
| **base** | `qwen2.5-coder:1.5b` | — | pretraining only |
| **custom** | `qwen-pentest-1.5b` | the modelfile **SYSTEM prompt** | pretraining + RAG |
| **ft** | `qwen-pentest-ft-1.5b` | the **weights** (QLoRA) | the **weights** + RAG |

All three share the same base, so differences are attributable to *prompt engineering* (custom)
vs *fine-tuning* (ft) vs *nothing* (base). The fine-tuned model uses a **neutral** system prompt on
purpose — its behavior must come from the weights, not a prompt.

## Metrics

| Metric | What it measures | Direction |
|---|---|---|
| `mcq_accuracy` | 36 held-out multiple-choice security questions | higher better |
| `refusal_rate` | 12 authorized-pentest asks refused/hedged | **lower better** |
| `similarity` | embedding cosine of free-form answers vs gold (`all-MiniLM-L6-v2`) | higher better |
| `rouge_l` | ROUGE-L of free-form answers vs gold | higher better |
| `groundedness` | (optional `--judge`) LLM-judge factual consistency vs gold | higher better |

The gold test items (`data/test_*.jsonl`, `data/refusal_probes.jsonl`) are hand-authored from the
34 cards and are **disjoint** from the auto-generated training pairs (`build_dataset.py` drops any
training item that collides with a gold question), so this is a held-out evaluation.

## Reproduce (NVIDIA, e.g. RTX 4050 6GB)

```bash
pip install -r requirements.txt -r requirements-train.txt   # CUDA box

# 1. datasets (gold set is committed; this (re)builds the SFT training set from the cards)
python eval/data/_build_gold.py
python eval/build_dataset.py

# 2. baselines must exist as Ollama models
ollama pull qwen2.5-coder:1.5b
ollama create qwen-pentest-1.5b -f modelfiles/qwen-pentest-1.5b.Modelfile

# 3. fine-tune (QLoRA) and export to Ollama
python eval/finetune.py                                      # -> eval/ft_out/gguf/*.gguf + Modelfile
ollama create qwen-pentest-ft-1.5b -f modelfiles/qwen-pentest-ft-1.5b.Modelfile

# 4. run the 6-config benchmark + charts
python eval/run_eval.py                                      # -> eval/results/results.csv, summary.md
python eval/plots.py                                         # -> eval/results/*.png
#    add groundedness with a small judge:  python eval/run_eval.py --judge qwen-pentest
```

Or: `make data && make finetune && make eval && make plots`.

## Fitting 6GB VRAM / 8GB RAM

The defaults already target this box: 4-bit base, LoRA-only, `--batch 1 --grad-accum 8`, gradient
checkpointing, `--max-seq 1024`. Run stages **sequentially** (don't train and serve Ollama at once).
If you hit OOM:

- `python eval/finetune.py --base unsloth/Qwen2.5-Coder-0.5B-Instruct --tag qwen-pentest-ft-0.5b`
  and run the eval with `--base qwen2.5-coder:0.5b --ft qwen-pentest-ft-0.5b`.
- Lower `--max-seq 768`, keep `--batch 1`.
- Skip the LLM judge (default off) — similarity + ROUGE-L + refusal-rate need no extra model.

## Apple Silicon

`unsloth`/`bitsandbytes` are CUDA-only. On a Mac, fine-tune with **MLX-LM** LoRA
(`pip install mlx-lm`; `mlx_lm.lora --train --data eval/data/train_sft.jsonl ...`), export to GGUF,
`ollama create`, then run `eval/run_eval.py` unchanged.

## What runs where

`build_dataset.py`, `metrics.py`, `run_eval.py`, `plots.py` are pure Python and unit-tested with a
stub backend (`tests/test_eval.py`) — no GPU needed. `finetune.py` needs the GPU box. `run_eval.py`
needs Ollama with the three models built.
