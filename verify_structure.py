import os
base = 'C:/temp/omniscience-cyber'

# Core files
files = [
    '.git',
    'IMPLEMENTATION.md',
    'README.md',
    'config.example.yaml',
    'Makefile',
    'requirements.txt',
    'LICENSE',
    'README.md',
    'REFERENCES.md',
    'config.example.yaml',
    'Makefile',
    'requirements.txt',
    # rag module
    'rag/__init__.py',
    'rag/models.py',
    'rag/parsers.py',
    'rag/executor.py',
    'rag/planner.py',
    'rag/state.py',
    'rag/findings.py',
    'rag/report.py',
    'rag/audit.py',
    'rag/api.py',
    'rag/shell.py',
    'rag/scope_guard.py',
    'rag/rag_core.py',
    'rag/verify.py',
    'rag/parsers.py',
    'rag/executor.py',
    'rag/planner.py',
    'rag/state.py',
    'rag/findings.py',
    'rag/report.py',
    'rag/audit.py',
    'rag/api.py',
    'rag/shell.py',
    'rag/__init__.py',
    # Modelfiles
    'modelfiles/qwen-pentest.Modelfile',
    'modelfiles/qwen-pentest-1.5b.Modelfile',
    'modelfiles/qwen-pentest-web.Modelfile',
    'modelfiles/qwen-pentest-infra.Modelfile',
    'modelfiles/qwen3.9-pentest.Modelfile',
    'modelfiles/qwen3.8-pentest.Modelfile',
    'modelfiles/qwen3-pentest-30b.Modelfile',
    'modelfiles/qwen3.6-pentest.Modelfile',
    'modelfiles/qwen-pentest-14b.Modelfile',
    'modelfiles/qwen-pentest-32b.Modelfile',
    'modelfiles/gemma-pentest.Modelfile',
    'modelfiles/gemma4-pentest.Modelfile',
    'modelfiles/mistral-pentest.Modelfile',
    'modelfiles/muse-pentest.Modelfile',
    'modelfiles/nemotron-pentest.Modelfile',
    'modelfiles/codestral-pentest.Modelfile',
]

base = 'C:/temp/omniscience-cyber'
print('File verification:')
all_exist = True
for f in files:
    exists = os.path.exists(os.path.join(base, f))
    status = 'EXISTS' if exists else 'MISSING'
    print(f'{f}: {status}')
    if not exists:
        all_exist = False

print(f'\nAll files exist: {all_exist}')