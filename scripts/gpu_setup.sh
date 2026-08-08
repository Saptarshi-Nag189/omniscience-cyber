#!/usr/bin/env bash
# gpu_setup.sh — one-command setup for omniscience-cyber. Run from the repo root.
# Pulls base models, builds the no-refuse *-pentest models, installs deps, ingests the cards.
# Needs: Ollama installed (https://ollama.com) + Python 3.10+. No sudo, no cloud.
set -uo pipefail
cd "$(dirname "$0")/.." 2>/dev/null || true   # repo root
echo "== omniscience-cyber setup =="

command -v ollama >/dev/null 2>&1 || { echo "!! install Ollama first: https://ollama.com/download"; exit 1; }

# 1) base models (GPU boxes: get the big ones; laptops: the 7b is enough)
echo "== pulling base models =="
ollama pull qwen2.5-coder:7b
ollama pull qwen2.5-coder:32b 2>/dev/null || echo "(skipped 32b — fine on low-VRAM)"
ollama pull gemma3:27b        2>/dev/null || echo "(skipped gemma3:27b — fine on low-VRAM)"

# 2) build the uncensored *-pentest models
echo "== building *-pentest models =="
ollama create qwen-pentest     -f modelfiles/qwen-pentest.Modelfile
ollama create qwen-pentest-32b -f modelfiles/qwen-pentest-32b.Modelfile 2>/dev/null || true
ollama create gemma-pentest    -f modelfiles/gemma-pentest.Modelfile    2>/dev/null || true

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
