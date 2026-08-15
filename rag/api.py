#!/usr/bin/env python3
"""
api.py — standalone local HTTP API for omniscience-cyber.

Exposes the offline RAG over HTTP so Kali/other tools can curl it. Pure stdlib
(http.server) — no Flask/FastAPI dependency. LAN-only by default; nothing leaves the box.

Security posture (this is a tool that emits attack commands — treat the API as sensitive):
  * Loopback-only by default. Binding a non-loopback address (0.0.0.0 / LAN) is
    FAIL-CLOSED: it requires an API token, or an explicit --insecure override.
  * Optional bearer-token auth on every endpoint except /health. Set the token via
    the OMNISCIENCE_API_TOKEN env var or `api_token:` in config.yaml. Compared in
    constant time. Clients send:  -H "Authorization: Bearer <token>".
  * Request bodies are size-capped (rejects oversized/garbage input).
  * Rules-of-Engagement enforcement: /tool output is filtered through scope_guard,
    so an out-of-scope or DoS command is BLOCKED before it reaches a shell.
  * Append-only local audit log of every request (who asked what, which model
    answered, what was blocked) — useful evidence for an authorized engagement.

Run:
  python rag/api.py --host 127.0.0.1 --port 8600
  # LAN (teammates): set a token first, then:  --host 0.0.0.0
  OMNISCIENCE_API_TOKEN=$(openssl rand -hex 16) python rag/api.py --host 0.0.0.0

Endpoints:
  GET  /health                         -> {"ok": true, "model": "..."}   (no auth)
  POST /ask     {"q": "...", "verify": false, "model": null, "think": null}
        -> {"answer","model","tried","cards","citations"[, "verdict"]}
        ("think": true = max accuracy/slower, false = max speed, null = default)
  POST /harden  {"q": "<finding / config / asset>", "think": null}   (DEFENSIVE: remediation)
        -> {"answer","model","tried","cards","citations"}
  POST /tool    {"task": "..."}         -> PLAIN TEXT: runnable Kali command(s), one per line
        (also GET /tool?task=...  — so it's shell-pipe friendly)
  POST /retrieve {"q": "...", "k": 4}   -> {"cards":[{id,source,text,score,distance}]}

Examples (from Kali — the /tool output feeds straight into a shell):
  curl -s localhost:8600/health
  curl -s -H "Authorization: Bearer $TOKEN" localhost:8600/ask -d '{"q":"how do I test IDOR?"}'
  curl -s 'localhost:8600/tool?task=directory+brute+force+with+ffuf'      # prints commands
"""
from __future__ import annotations
import argparse
import datetime
import hmac
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rag_core import RagCore  # noqa: E402

try:
    import yaml
except Exception:
    yaml = None


ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = 64 * 1024          # reject request bodies larger than 64 KiB
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def load_cfg() -> dict:
    for name in ("config.yaml", "config.example.yaml"):
        p = ROOT / name
        if p.is_file() and yaml is not None:
            try:
                return yaml.safe_load(p.read_text()) or {}
            except Exception:
                pass
    return {}


CFG = load_cfg()
RAG = RagCore(CFG)

# API token: env var wins over config. Empty/None => no auth required (loopback dev).
API_TOKEN = (os.environ.get("OMNISCIENCE_API_TOKEN")
             or str(CFG.get("api_token") or "")).strip() or None

# Audit log (append-only JSONL). Configurable; disable with audit_log: false.
_audit_cfg = CFG.get("audit_log", "logs/audit.jsonl")
AUDIT_PATH = None if _audit_cfg in (False, "false", "off", "") else (ROOT / str(_audit_cfg))
_audit_lock = threading.Lock()


def _audit(event: dict) -> None:
    """Append one JSON line to the audit log. Never raises."""
    if AUDIT_PATH is None:
        return
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        event = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(), **event}
        with _audit_lock, AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


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
    server_version = "omniscience-cyber"

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

    def _authed(self) -> bool:
        """True if no token is configured, or the request presents the right one."""
        if not API_TOKEN:
            return True
        hdr = self.headers.get("Authorization", "")
        prefix = "Bearer "
        supplied = hdr[len(prefix):].strip() if hdr.startswith(prefix) else ""
        # constant-time compare to avoid leaking the token via timing
        return hmac.compare_digest(supplied, API_TOKEN)

    def _reject_unauthed(self, text_mode: bool) -> bool:
        """Send 401 if not authed. Returns True when it rejected (caller should stop)."""
        if self._authed():
            return False
        _audit({"event": "unauthorized", "ip": self.client_address[0], "path": self.path})
        if text_mode:
            self._send_text(401, "# 401 unauthorized: send Authorization: Bearer <token>")
        else:
            self._send(401, {"error": "unauthorized",
                             "hint": "send header: Authorization: Bearer <token>"})
        return True

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return None, "bad Content-Length"
        if n < 0 or n > MAX_BODY:
            return None, f"body too large (max {MAX_BODY} bytes)"
        try:
            return json.loads(self.rfile.read(n) or b"{}"), None
        except Exception:
            return None, "invalid JSON body"

    def log_message(self, *a):  # quiet — we keep our own audit log
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path.startswith("/health"):
            # health is unauthenticated but minimal — no config leakage
            return self._send(200, {"ok": True, "model": RAG.model,
                                    "auth": bool(API_TOKEN)})
        if parsed.path.startswith("/tool"):
            if self._reject_unauthed(text_mode=True):
                return
            task = (parse_qs(parsed.query).get("task", [""])[0]).strip()
            if not task:
                return self._send_text(400, "# missing 'task' query param")
            return self._handle_tool(task, None, json_out=False)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        is_tool = self.path.startswith("/tool")
        if self._reject_unauthed(text_mode=is_tool):
            return
        data, err = self._body()
        if err:
            return (self._send_text(413 if "large" in err else 400, f"# {err}")
                    if is_tool else self._send(413 if "large" in err else 400, {"error": err}))
        if is_tool:
            task = (data.get("task") or data.get("q") or "").strip()
            if not task:
                return self._send_text(400, "# missing 'task'")
            return self._handle_tool(task, data.get("model"), json_out=bool(data.get("json")),
                                     think=data.get("think"))
        q = (data.get("q") or "").strip()
        if not q:
            return self._send(400, {"error": "missing 'q'"})
        try:
            if self.path.startswith("/retrieve"):
                hits = RAG.retrieve(q, int(data.get("k", RAG.top_k)))
                return self._send(200, {"cards": hits})
            if self.path.startswith("/ask"):
                r = RAG.ask(q, model=data.get("model"), think=data.get("think"))
                out = {"answer": r["answer"], "model": r["model"], "tried": r["tried"],
                       "cards": r["cards"], "citations": r.get("citations")}
                if data.get("verify"):
                    out["verdict"] = _verify(q, r["context"], r["answer"], r["model"])
                _audit({"event": "ask", "ip": self.client_address[0], "q": q,
                        "model": r["model"], "verify": bool(data.get("verify"))})
                return self._send(200, out)
            if self.path.startswith("/harden"):
                r = RAG.harden(q, model=data.get("model"), think=data.get("think"))
                _audit({"event": "harden", "ip": self.client_address[0], "q": q,
                        "model": r["model"]})
                return self._send(200, {"answer": r["answer"], "model": r["model"],
                                        "tried": r["tried"], "cards": r["cards"],
                                        "citations": r.get("citations")})
            return self._send(404, {"error": "unknown endpoint"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def _handle_tool(self, task, model, json_out, think=None):
        try:
            r = RAG.tool(task, model=model, think=think)
        except Exception as e:
            return self._send_text(500, f"# error: {e}")
        _audit({"event": "tool", "ip": self.client_address[0], "task": task,
                "model": r.get("model"), "blocked": r.get("blocked", [])})
        if json_out:
            return self._send(200, r)
        return self._send_text(200, "\n".join(r["commands"]) or "# (no command produced)")


def main():
    ap = argparse.ArgumentParser(description="omniscience-cyber local RAG API")
    ap.add_argument("--host", default="127.0.0.1", help="127.0.0.1 (local) or 0.0.0.0 (LAN)")
    ap.add_argument("--port", type=int, default=8600)
    ap.add_argument("--insecure", action="store_true",
                    help="allow non-loopback bind with NO token (NOT recommended)")
    args = ap.parse_args()

    # Fail-closed: a non-loopback bind exposes a command generator to the network.
    # Refuse unless a token is set (or --insecure is explicitly passed).
    if args.host not in _LOOPBACK and not API_TOKEN and not args.insecure:
        print("[api] REFUSING to bind a non-loopback address without an API token.\n"
              "      This endpoint generates attack commands — exposing it unauthenticated\n"
              "      on the LAN is dangerous. Either:\n"
              "        • set a token:  OMNISCIENCE_API_TOKEN=$(openssl rand -hex 16) "
              "python rag/api.py --host 0.0.0.0\n"
              "        • or bind loopback:  --host 127.0.0.1\n"
              "        • or (not recommended) pass --insecure to override.",
              file=sys.stderr)
        raise SystemExit(2)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    auth = "token-protected" if API_TOKEN else "NO AUTH"
    print(f"[api] omniscience-cyber serving on http://{args.host}:{args.port}  "
          f"(model={RAG.model}, {auth})")
    if args.host not in _LOOPBACK:
        print("[api] bound non-loopback — reachable from the LAN. Token required for all "
              "endpoints except /health.")
    else:
        print("[api] loopback-only — not reachable from other hosts. Ctrl-C to stop.")
    if AUDIT_PATH is not None:
        print(f"[api] audit log: {AUDIT_PATH}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[api] stopped.")


if __name__ == "__main__":
    main()
