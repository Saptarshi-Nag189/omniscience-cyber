#!/usr/bin/env bash
# gpu_setup.sh — one-command setup for omniscience-cyber. Run from the repo root.
# Pulls base models, builds the no-refuse *-pentest models, installs deps, ingests the cards.
# Needs: Ollama installed (https://ollama.com) + Python 3.10+. No sudo, no cloud.
set -uo pipefail
cd "$(dirname "$0")/.." 2>/dev/null || true   # repo root
echo "== omniscience-cyber setup =="

command -v ollama >/dev/null 2>&1 || { echo "!! install Ollama first: https://ollama.com/download"; exit 1; }

# 1) base models. Latest 2025/2026 models are pulled best-effort (skip cleanly if a tag/VRAM
#    isn't available). The 7B always pulls so you have a guaranteed-working generator.
echo "== pulling base models =="
ollama pull qwen2.5-coder:7b                                      # always (light safety net)
# 16GB-friendly gap fillers:
ollama pull gemma4:12b            2>/dev/null || echo "(skip gemma4:12b)"
ollama pull codestral:22b        2>/dev/null || echo "(skip codestral:22b)"
ollama pull qwen2.5-coder:14b    2>/dev/null || echo "(skip qwen2.5-coder:14b — optional 14B)"
# 24B+ / newest (need more VRAM or offload on 16GB):
ollama pull mistral-small:24b    2>/dev/null || echo "(skip mistral-small:24b)"
ollama pull qwen3.8              2>/dev/null || echo "(skip qwen3.8)"
ollama pull qwen3-coder:30b      2>/dev/null || echo "(skip qwen3-coder:30b)"
ollama pull qwen3.6:35b          2>/dev/null || echo "(skip qwen3.6:35b)"
ollama pull muse-glimmer         2>/dev/null || echo "(skip muse-glimmer)"
ollama pull nemotron-3.5-lightning 2>/dev/null || echo "(skip nemotron-3.5-lightning)"
# legacy bases (older wrappers still available):
ollama pull qwen2.5-coder:32b    2>/dev/null || echo "(skip qwen2.5-coder:32b)"
ollama pull gemma3:27b           2>/dev/null || echo "(skip gemma3:27b)"

# 2) build the uncensored *-pentest wrappers (only those whose base actually pulled succeed;
#    the rest are skipped with '|| true' so setup never aborts).
echo "== building *-pentest models =="
build() { ollama create "$1" -f "modelfiles/$1.Modelfile" 2>/dev/null && echo "  built $1" || echo "  (skip $1 — base not pulled)"; }
build qwen-pentest                # 7B — guaranteed
for m in gemma4-pentest codestral-pentest qwen-pentest-14b mistral-pentest \
         qwen3.8-pentest qwen3-pentest-30b qwen3.6-pentest muse-pentest nemotron-pentest \
         qwen-pentest-32b gemma-pentest; do
  build "$m"
done

# 3) python deps
echo "== python deps =="
if [ ! -d .venv ]; then python3 -m venv .venv; fi
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -r requirements.txt

# 4) config + ingest the cards
[ -f config.yaml ] || cp config.example.yaml config.yaml
echo "== ingesting distilled cards =="
.venv/bin/python rag/rag_core.py ingest cards || echo "(ingest failed — check Ollama/deps)"

echo
echo "== DONE =="
echo "  Test models:  bash scripts/test_llms.sh"
echo "  Ask:          .venv/bin/python rag/rag_core.py ask \"how do I test for IDOR?\""
ollama list | grep -E "pentest" || true
