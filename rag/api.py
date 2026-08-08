#!/usr/bin/env python3
"""
api.py — standalone local HTTP API for omniscience-cyber.

Exposes the offline RAG over HTTP so Kali/other tools can curl it. Pure stdlib
(http.server) — no Flask/FastAPI dependency. LAN-only by default; nothing leaves the box.

Run:
  python rag/api.py --host 127.0.0.1 --port 8600
  # LAN (teammates on the same network):  --host 0.0.0.0

Endpoints:
  GET  /health                         -> {"ok": true, "model": "..."}
  POST /ask     {"q": "...", "verify": false, "model": null}
        -> {"answer","model","tried","cards"[, "verdict"]}
  POST /tool    {"task": "..."}         -> PLAIN TEXT: runnable Kali command(s), one per line
        (also GET /tool?task=...  — so it's shell-pipe friendly)
  POST /retrieve {"q": "...", "k": 4}   -> {"cards":[{id,source,text}]}

Examples (from Kali — the /tool output feeds straight into a shell):
  curl -s localhost:8600/health
  curl -s localhost:8600/ask  -d '{"q":"how do I test for IDOR and score it?"}'
  curl -s localhost:8600/ask  -d '{"q":"CVSS for reflected XSS?","verify":true}'
  curl -s 'localhost:8600/tool?task=directory+brute+force+with+ffuf'      # prints commands
  curl -s 'localhost:8600/tool?task=nuclei+scan+the+target' | bash        # (review first!)
"""
from __future__ import annotations
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rag_core import RagCore  # noqa: E402

try:
    import yaml
except Exception:
    yaml = None


def load_cfg() -> dict:
    root = Path(__file__).resolve().parent.parent
    for name in ("config.yaml", "config.example.yaml"):
        p = root / name
        if p.is_file() and yaml is not None:
            try:
                return yaml.safe_load(p.read_text()) or {}
            except Exception:
                pass
    return {}


CFG = load_cfg()
RAG = RagCore(CFG)


def _verify(question, context, answer, model):
    """Optional second-model check. Never raises — returns None if unavailable."""
    try:
        from verify import verify_answer
        v = verify_answer(question, context, answer, generator_model=model or RAG.model)
        return {"status": v.status, "badge": v.badge(),
                "issues": [{"kind": i.kind, "detail": i.detail} for i in v.issues]}
    except Exception as e:
        return {"status": "UNCHECKED", "badge": f"(verifier unavailable: {e})", "issues": []}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code, text):
        body = (text + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path.startswith("/health"):
            return self._send(200, {"ok": True, "model": RAG.model, "fallbacks": RAG.fallbacks})
        if parsed.path.startswith("/tool"):
            task = (parse_qs(parsed.query).get("task", [""])[0]).strip()
            if not task:
                return self._send_text(400, "# missing 'task' query param")
            try:
                r = RAG.tool(task)
                return self._send_text(200, "\n".join(r["commands"]) or "# (no command produced)")
            except Exception as e:
                return self._send_text(500, f"# error: {e}")
        self._send(404, {"error": "not found"})

    def do_POST(self):
        data = self._body()
        # /tool takes 'task'; everything else takes 'q'
        if self.path.startswith("/tool"):
            task = (data.get("task") or data.get("q") or "").strip()
            if not task:
                return self._send_text(400, "# missing 'task'")
            try:
                r = RAG.tool(task, model=data.get("model"))
                if data.get("json"):
                    return self._send(200, r)
                return self._send_text(200, "\n".join(r["commands"]) or "# (no command produced)")
            except Exception as e:
                return self._send_text(500, f"# error: {e}")
        q = (data.get("q") or "").strip()
        if not q:
            return self._send(400, {"error": "missing 'q'"})
        try:
            if self.path.startswith("/retrieve"):
                hits = RAG.retrieve(q, int(data.get("k", RAG.top_k)))
                return self._send(200, {"cards": hits})
            if self.path.startswith("/ask"):
                r = RAG.ask(q, model=data.get("model"))
                out = {"answer": r["answer"], "model": r["model"],
                       "tried": r["tried"], "cards": r["cards"]}
                if data.get("verify"):
                    out["verdict"] = _verify(q, r["context"], r["answer"], r["model"])
                return self._send(200, out)
            return self._send(404, {"error": "unknown endpoint"})
        except Exception as e:
            return self._send(500, {"error": str(e)})


def main():
    ap = argparse.ArgumentParser(description="omniscience-cyber local RAG API")
    ap.add_argument("--host", default="127.0.0.1", help="127.0.0.1 (local) or 0.0.0.0 (LAN)")
    ap.add_argument("--port", type=int, default=8600)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[api] omniscience-cyber serving on http://{args.host}:{args.port}  "
          f"(model={RAG.model}, fallbacks={RAG.fallbacks})")
    print("[api] LAN-only — do NOT expose to the internet. Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[api] stopped.")


if __name__ == "__main__":
    main()
