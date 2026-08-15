#!/usr/bin/env bash
# ollama_serve_lowvram.sh — start Ollama with a smaller memory footprint.
#
# The KV cache (attention memory) can dominate VRAM, especially for these long-context models.
# Quantizing it and enabling flash attention cuts that memory a lot with negligible quality loss:
#   OLLAMA_FLASH_ATTENTION=1     — required for KV-cache quantization; also saves attention memory
#   OLLAMA_KV_CACHE_TYPE=q8_0    — half-size KV cache vs f16 (q4_0 = quarter-size, a bit lossier)
#
# These are SERVER settings, so they must be set on the `ollama serve` process (not per request or
# in a Modelfile). Run this INSTEAD of a plain `ollama serve`, then use omniscience-cyber as usual.
#
# Usage:
#   ./scripts/ollama_serve_lowvram.sh              # q8_0 KV cache (recommended)
#   KV=q4_0 ./scripts/ollama_serve_lowvram.sh      # even smaller, slightly lossier
set -uo pipefail

KV="${KV:-q8_0}"
export OLLAMA_FLASH_ATTENTION=1
export OLLAMA_KV_CACHE_TYPE="$KV"

echo "== starting ollama serve (low-VRAM) =="
echo "   OLLAMA_FLASH_ATTENTION=$OLLAMA_FLASH_ATTENTION"
echo "   OLLAMA_KV_CACHE_TYPE=$OLLAMA_KV_CACHE_TYPE"
echo "   (combine with the lean num_ctx in the modelfiles for the biggest saving)"
exec ollama serve
