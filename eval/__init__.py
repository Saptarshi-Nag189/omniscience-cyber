"""
eval/ — small-model fine-tuning + a 6-configuration benchmark harness.

Quantifies three ways of specializing one small base model (Qwen2.5-Coder-1.5B) for the
authorized-pentest domain — raw base, custom-modelfile (uncensored via system prompt), and
QLoRA fine-tuned (uncensored + domain knowledge in the weights) — each measured WITH and
WITHOUT retrieval (RAG), for 3 x 2 = 6 results.

Modules:
  metrics.py        pure scoring functions (MCQ accuracy, refusal rate, similarity, ROUGE-L)
  build_dataset.py  cards -> SFT training JSONL (+ card-level train/test split)
  run_eval.py       run the 6 configs over the gold test set, write results.csv / summary.md
  finetune.py       Unsloth QLoRA training + GGUF/Ollama export (user-side, needs GPU)
  plots.py          grouped bar charts for the writeup
"""
