# omniscience-cyber — convenience targets. No sudo, all local/offline.
.PHONY: setup models ingest serve serve-ollama test test-guard ask data finetune eval plots test-eval bench-all bench-models

setup:            ## full setup: models + deps + ingest
	bash scripts/gpu_setup.sh

models:           ## build the uncensored *-pentest Ollama models (skips any whose base isn't pulled)
	ollama create qwen-pentest -f modelfiles/qwen-pentest.Modelfile
	-ollama create qwen-pentest-1.5b -f modelfiles/qwen-pentest-1.5b.Modelfile
	-ollama create qwen-pentest-web -f modelfiles/qwen-pentest-web.Modelfile
	-ollama create qwen-pentest-infra -f modelfiles/qwen-pentest-infra.Modelfile
	-ollama create gemma4-pentest -f modelfiles/gemma4-pentest.Modelfile
	-ollama create codestral-pentest -f modelfiles/codestral-pentest.Modelfile
	-ollama create qwen-pentest-14b -f modelfiles/qwen-pentest-14b.Modelfile
	-ollama create mistral-pentest -f modelfiles/mistral-pentest.Modelfile
	-ollama create qwen3.9-pentest -f modelfiles/qwen3.9-pentest.Modelfile
	-ollama create qwen3.8-pentest -f modelfiles/qwen3.8-pentest.Modelfile
	-ollama create qwen3-pentest-30b -f modelfiles/qwen3-pentest-30b.Modelfile
	-ollama create qwen3.6-pentest -f modelfiles/qwen3.6-pentest.Modelfile
	-ollama create muse-pentest -f modelfiles/muse-pentest.Modelfile
	-ollama create nemotron-pentest -f modelfiles/nemotron-pentest.Modelfile
	-ollama create qwen-pentest-32b -f modelfiles/qwen-pentest-32b.Modelfile
	-ollama create gemma-pentest -f modelfiles/gemma-pentest.Modelfile

ingest:           ## (re)build the local vector DB from cards/
	python rag/rag_core.py ingest cards

serve:            ## start the HTTP API for Kali/other tools (localhost:8600)
	python rag/api.py --host 127.0.0.1 --port 8600

serve-ollama:     ## start Ollama in low-VRAM mode (flash attn + q8_0 KV cache)
	bash scripts/ollama_serve_lowvram.sh

test:             ## prove the models don't refuse / don't fabricate
	bash scripts/test_llms.sh

test-guard:       ## offline unit test of the Rules-of-Engagement scope guard (no Ollama)
	python rag/scope_guard.py --self-test

ask:              ## one-off question: make ask Q="how do I test IDOR?"
	python rag/rag_core.py ask "$(Q)"

# ── fine-tuning + benchmark (eval/) ───────────────────────────────────────────
data:             ## (re)build the gold test set + SFT training set from cards
	python eval/data/_build_gold.py
	python eval/build_dataset.py

finetune:         ## QLoRA fine-tune the 1.5B base (needs GPU + requirements-train.txt)
	python eval/finetune.py

eval:             ## run the 6-config benchmark (needs Ollama + the 3 models built)
	python eval/run_eval.py

plots:            ## render result charts from eval/results/results.csv
	python eval/plots.py

test-eval:        ## offline unit tests for the eval harness (no GPU/Ollama)
	python -m pytest tests/test_eval.py -q

# ── one-command benchmark pipeline ────────────────────────────────────────────
# Override any of these to run a different size, e.g. the 0.5B fallback:
#   make bench-all FT_BASE=unsloth/Qwen2.5-Coder-0.5B-Instruct FT_TAG=qwen-pentest-ft-0.5b BASE_OLLAMA=qwen2.5-coder:0.5b
# (Comments are kept on their own lines: a trailing inline comment would leave whitespace in the
#  value and corrupt the model tags / file paths.)
FT_BASE     ?= unsloth/Qwen2.5-Coder-1.5B-Instruct
BASE_OLLAMA ?= qwen2.5-coder:1.5b
CUSTOM_TAG  ?= qwen-pentest-1.5b
FT_TAG      ?= qwen-pentest-ft-1.5b
JUDGE       ?=

bench-models:     ## pull/build just the baselines the benchmark needs
	ollama pull $(BASE_OLLAMA)
	ollama create $(CUSTOM_TAG) -f modelfiles/$(CUSTOM_TAG).Modelfile

bench-all:        ## END-TO-END: datasets -> baselines -> QLoRA -> ft model -> eval -> charts
	@echo "== [1/6] datasets =="
	$(MAKE) data
	@echo "== [2/6] baseline models =="
	$(MAKE) bench-models
	@echo "== [3/6] QLoRA fine-tune (GPU) =="
	python eval/finetune.py --base $(FT_BASE) --tag $(FT_TAG)
	@echo "== [4/6] build fine-tuned Ollama model =="
	ollama create $(FT_TAG) -f modelfiles/$(FT_TAG).Modelfile
	@echo "== [5/6] run 6-config benchmark =="
	python eval/run_eval.py --base $(BASE_OLLAMA) --custom $(CUSTOM_TAG) --ft $(FT_TAG) $(if $(JUDGE),--judge $(JUDGE),)
	@echo "== [6/6] charts =="
	$(MAKE) plots
	@echo "== done -> eval/results/ (results.csv, summary.md, *.png); fill in eval/RESULTS.md =="
