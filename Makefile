# omniscience-cyber — convenience targets. No sudo, all local/offline.
.PHONY: setup models ingest serve serve-ollama test test-guard ask

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
