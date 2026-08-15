# omniscience-cyber — convenience targets. No sudo, all local/offline.
.PHONY: setup models ingest serve test test-guard ask

setup:            ## full setup: models + deps + ingest
	bash scripts/gpu_setup.sh

models:           ## build the uncensored *-pentest Ollama models
	ollama create qwen-pentest -f modelfiles/qwen-pentest.Modelfile
	-ollama create qwen-pentest-32b -f modelfiles/qwen-pentest-32b.Modelfile
	-ollama create gemma-pentest -f modelfiles/gemma-pentest.Modelfile

ingest:           ## (re)build the local vector DB from cards/
	python rag/rag_core.py ingest cards

serve:            ## start the HTTP API for Kali/other tools (localhost:8600)
	python rag/api.py --host 127.0.0.1 --port 8600

test:             ## prove the models don't refuse / don't fabricate
	bash scripts/test_llms.sh

test-guard:       ## offline unit test of the Rules-of-Engagement scope guard (no Ollama)
	python rag/scope_guard.py --self-test

ask:              ## one-off question: make ask Q="how do I test IDOR?"
	python rag/rag_core.py ask "$(Q)"
