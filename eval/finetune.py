#!/usr/bin/env python3
"""
eval/finetune.py — QLoRA fine-tune Qwen2.5-Coder-1.5B on the security SFT set, then export to
GGUF + an Ollama model so it drops into the same eval harness.

This runs on the USER's GPU box (needs CUDA + unsloth/trl/peft/bitsandbytes). It is deliberately
tuned for a 6GB-VRAM / 8GB-RAM laptop (RTX 4050): 4-bit base, LoRA only, batch=1 + grad-accum,
gradient checkpointing, short sequence length. Training time is not optimized for — correctness
and fitting in memory are.

Pipeline:
  1. Load base in 4-bit (Unsloth) + attach LoRA.
  2. SFT on eval/data/train_sft.jsonl (Qwen chat template) with TRL SFTTrainer.
  3. Save the LoRA adapter, then export a q4_K_M GGUF.
  4. Write modelfiles/qwen-pentest-ft-1.5b.Modelfile (NEUTRAL system prompt — the uncensoring +
     domain knowledge live in the weights) and print the `ollama create` command.

Usage:
  python eval/finetune.py                          # 1.5B, 2 epochs
  python eval/finetune.py --base unsloth/Qwen2.5-Coder-0.5B-Instruct --tag qwen-pentest-ft-0.5b
  # then:  ollama create qwen-pentest-ft-1.5b -f modelfiles/qwen-pentest-ft-1.5b.Modelfile
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "eval" / "data" / "train_sft.jsonl"

# Neutral system prompt for the fine-tuned model: NO uncensoring text — we want to measure what
# the weights learned. Kept minimal so behavior is attributable to fine-tuning, not the prompt.
NEUTRAL_SYSTEM = "You are a penetration-testing assistant for authorized, in-scope security engagements."

MODELFILE_TEMPLATE = """\
# qwen-pentest-ft-1.5b — QLoRA fine-tune of Qwen2.5-Coder-1.5B on the security cards.
# Built by eval/finetune.py. Domain knowledge + no-refusal behavior are in the WEIGHTS, so the
# system prompt is intentionally neutral (contrast this with qwen-pentest-1.5b, which is uncensored
# purely via its system prompt). For measuring what fine-tuning learned.
FROM {gguf}

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER repeat_penalty 1.1
PARAMETER num_ctx 8192

SYSTEM \"\"\"{system}\"\"\"
"""


def load_dataset(tokenizer):
    from datasets import Dataset
    rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
    texts = [tokenizer.apply_chat_template(r["messages"], tokenize=False, add_generation_prompt=False)
             for r in rows]
    return Dataset.from_dict({"text": texts})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="unsloth/Qwen2.5-Coder-1.5B-Instruct",
                    help="HF/Unsloth base model id")
    ap.add_argument("--tag", default="qwen-pentest-ft-1.5b", help="Ollama tag / output name")
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--max-seq", type=int, default=1024)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--out", default=str(ROOT / "eval" / "ft_out"))
    ap.add_argument("--quant", default="q4_k_m", help="GGUF quantization for export")
    ap.add_argument("--no-gguf", action="store_true", help="skip GGUF export (adapter only)")
    args = ap.parse_args()

    try:
        from unsloth import FastLanguageModel
        from trl import SFTTrainer, SFTConfig
    except Exception as e:  # pragma: no cover - user-side only
        raise SystemExit(
            f"[finetune] missing training deps ({e}). Install with:\n"
            f"    pip install -r requirements-train.txt\n"
            f"(needs a CUDA GPU; on Apple Silicon use MLX-LM instead — see eval/README.md)")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # 1) base in 4-bit + LoRA
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base, max_seq_length=args.max_seq, load_in_4bit=True, dtype=None)
    model = FastLanguageModel.get_peft_model(
        model, r=args.lora_r, lora_alpha=args.lora_r, lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth", random_state=42)

    # 2) SFT
    dataset = load_dataset(tokenizer)
    trainer = SFTTrainer(
        model=model, tokenizer=tokenizer, train_dataset=dataset,
        args=SFTConfig(
            per_device_train_batch_size=args.batch,
            gradient_accumulation_steps=args.grad_accum,
            warmup_ratio=0.05, num_train_epochs=args.epochs,
            learning_rate=args.lr, logging_steps=10, optim="adamw_8bit",
            weight_decay=0.01, lr_scheduler_type="linear", seed=42,
            max_seq_length=args.max_seq, dataset_text_field="text",
            output_dir=str(out / "checkpoints"), report_to="none"))
    trainer.train()

    # 3) save adapter + GGUF
    model.save_pretrained(str(out / "adapter"))
    tokenizer.save_pretrained(str(out / "adapter"))
    print(f"[finetune] LoRA adapter -> {out/'adapter'}")

    if not args.no_gguf:
        gguf_dir = out / "gguf"
        model.save_pretrained_gguf(str(gguf_dir), tokenizer, quantization_method=args.quant)
        gguf = next(gguf_dir.glob("*.gguf"), gguf_dir / "model.gguf")
        modelfile = ROOT / "modelfiles" / f"{args.tag}.Modelfile"
        modelfile.write_text(MODELFILE_TEMPLATE.format(gguf=gguf, system=NEUTRAL_SYSTEM))
        print(f"[finetune] wrote {modelfile}\n[finetune] now run:\n"
              f"    ollama create {args.tag} -f {modelfile}")


if __name__ == "__main__":
    main()
