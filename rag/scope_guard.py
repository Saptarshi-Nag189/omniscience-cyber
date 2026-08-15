#!/usr/bin/env python3
"""
scope_guard.py — Rules-of-Engagement (RoE) enforcement for omniscience-cyber.

The README and config promise "you set the guardrails" (in_scope_hosts, forbid,
require), and verify.py / the test scripts tell the model to "defer to scope_guard".
This module is that guard: a small, offline, dependency-free enforcement layer that
inspects a GENERATED Kali command and decides whether running it would stay inside
the engagement's rules of engagement.

It does two things, both LOCAL and deterministic:

  1. SCOPE — extract every host/IP/URL a command targets and check it against the
     engagement's `in_scope_hosts`. Anything not on the list is out of scope.
  2. RULES OF ENGAGEMENT — scan the command for patterns that map to a `forbid`
     rule (denial-of-service / stress flags, bulk-PII exfiltration like
     `sqlmap --dump-all`, unthrottled brute-force, etc.).

The result is advisory-by-default but fail-closed on the dangerous stuff: the API
and wrapper scripts use it to BLOCK an out-of-scope or DoS command before it is
ever handed to a shell, and to annotate everything else with the scope decision.

Nothing here talks to a model or the network — it is pure string analysis so it
can run air-gapped and be unit-tested without Ollama.

Public API:
  guard = ScopeGuard.from_config(cfg)          # cfg = loaded config dict
  decision = guard.check_command("ffuf -u https://api.staging.example.com/FUZZ ...")
  # decision.verdict in {"allow", "warn", "block"}; decision.reasons is a list.
  hosts = guard.extract_targets(command)       # just the hosts/IPs a command hits
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable


# ── Forbidden / dangerous command patterns, grouped by the `forbid` rule they map to ──
# Each entry: (compiled regex, forbid-rule-key, human reason). Kept conservative — we
# only match things that are unambiguously a DoS / bulk-exfil / unthrottled action so
# legitimate impact-limited PoCs are not blocked.
_DANGER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ── denial-of-service / stress ────────────────────────────────────────────
    (re.compile(r"\bhping3?\b.*(--flood|--faster|-i\s*u\d)", re.I),
     "dos_or_stress_testing", "hping flood/stress flags"),
    (re.compile(r"\b(slowloris|slowhttptest|t50|mhddos|goldeneye)\b", re.I),
     "dos_or_stress_testing", "DoS/stress tool"),
    (re.compile(r"\bab\b.*-n\s*\d{5,}", re.I),
     "dos_or_stress_testing", "ApacheBench with a very large request count"),
    (re.compile(r"\bwrk\b.*-c\s*\d{3,}", re.I),
     "dos_or_stress_testing", "wrk with a very high connection count"),
    (re.compile(r"--flood\b", re.I),
     "dos_or_stress_testing", "explicit --flood flag"),
    # ── bulk / real-PII exfiltration (PoC must stay impact-limited) ────────────
    (re.compile(r"\bsqlmap\b.*--dump-all\b", re.I),
     "bulk_real_pii_exfiltration", "sqlmap --dump-all pulls entire databases"),
    (re.compile(r"\bsqlmap\b.*(--dump\b(?!.*(--start|--stop|--where|-C\b)))", re.I),
     "bulk_real_pii_exfiltration",
     "sqlmap --dump without --start/--stop/--where/-C bounds (unbounded dump)"),
    (re.compile(r"\bsqlmap\b.*--os-shell\b", re.I),
     "bulk_real_pii_exfiltration", "sqlmap --os-shell (full OS command execution)"),
    # ── unthrottled / aggressive brute force ──────────────────────────────────
    (re.compile(r"\bhydra\b(?!.*-t\s*\d)", re.I),
     "dos_or_stress_testing", "hydra without a -t task/throttle limit"),
    (re.compile(r"\bhydra\b.*-t\s*(?:[6-9]\d|\d{3,})", re.I),
     "dos_or_stress_testing", "hydra with a very high -t task count (>=60)"),
    (re.compile(r"\bnmap\b.*(-T5\b|--min-rate\s*(?:[1-9]\d{4,}))", re.I),
     "dos_or_stress_testing", "nmap insane timing (-T5) / very high --min-rate"),
    (re.compile(r"\bffuf\b.*-rate\s*0\b", re.I),
     "dos_or_stress_testing", "ffuf -rate 0 (unlimited request rate)"),
]

# Tokens that clearly are NOT targets even though they look host-ish.
_PLACEHOLDER_HOSTS = {"<target>", "target", "example.com", "localhost", "127.0.0.1"}

# File extensions that make a token a filename (wordlist, script, output), NOT a host.
# `rockyou.txt` / `payloads.json` must never be read as a target.
_FILE_EXTS = {
    "txt", "lst", "list", "dic", "dict", "py", "sh", "rb", "pl", "php", "js", "ts",
    "json", "yaml", "yml", "xml", "html", "htm", "css", "md", "conf", "cfg", "ini",
    "log", "csv", "tsv", "pdf", "doc", "docx", "xls", "xlsx", "zip", "gz", "tar",
    "tgz", "bz2", "7z", "png", "jpg", "jpeg", "gif", "svg", "pcap", "cap", "pem",
    "key", "crt", "cer", "der", "db", "sqlite", "bak", "out", "tmp", "env", "so",
}


@dataclass
class Decision:
    """Outcome of inspecting one command."""
    verdict: str                                   # "allow" | "warn" | "block"
    command: str = ""
    targets: list = field(default_factory=list)    # hosts/IPs the command touches
    out_of_scope: list = field(default_factory=list)
    reasons: list = field(default_factory=list)    # human-readable strings
    forbidden_hits: list = field(default_factory=list)   # (rule, reason) tuples

    @property
    def allowed(self) -> bool:
        return self.verdict != "block"

    def annotation(self) -> str:
        """A single `# ...` comment line describing the decision, for shell output."""
        if self.verdict == "allow":
            tgt = ", ".join(self.targets) if self.targets else "no explicit host"
            return f"# scope: OK ({tgt})"
        prefix = "# BLOCKED" if self.verdict == "block" else "# WARNING"
        return f"{prefix}: " + "; ".join(self.reasons)


class ScopeGuard:
    def __init__(self, in_scope_hosts: Iterable[str] | None = None,
                 forbid: Iterable[str] | None = None,
                 block_out_of_scope: bool = True):
        self.in_scope_hosts = [h.strip().lower() for h in (in_scope_hosts or []) if h and h.strip()]
        self.forbid = set(forbid or [])
        # If no scope list is configured we can't decide scope, so we WARN rather than
        # BLOCK on scope (the operator hasn't told us what's in scope yet).
        self.block_out_of_scope = block_out_of_scope and bool(self.in_scope_hosts)

    @classmethod
    def from_config(cls, cfg: dict | None) -> "ScopeGuard":
        g = (cfg or {}).get("guardrails", {}) or {}
        return cls(in_scope_hosts=g.get("in_scope_hosts", []),
                   forbid=g.get("forbid", []))

    # ── target extraction ─────────────────────────────────────────────────────
    _URL_RE = re.compile(r"https?://([^/\s\"'<>|]+)", re.I)
    # host:port or bare host/IP that appears as a standalone token
    _HOST_RE = re.compile(
        r"(?<![\w.-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
        r"|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?![\w.-])")

    def extract_targets(self, command: str) -> list[str]:
        """Best-effort host/IP extraction from a command line. De-duplicated, lowercased."""
        found: list[str] = []
        cmd = command or ""
        for m in self._URL_RE.finditer(cmd):
            host = m.group(1).split("@")[-1].split(":")[0].lower()
            found.append(host)
        for m in self._HOST_RE.finditer(cmd):
            host = m.group(1).split(":")[0].lower()
            found.append(host)
        out: list[str] = []
        for h in found:
            if not h or h in _PLACEHOLDER_HOSTS or h.startswith("<"):
                continue
            # skip filenames (rockyou.txt, payloads.json, …) — not targets
            last = h.rsplit(".", 1)[-1]
            if last in _FILE_EXTS and not h.replace(".", "").isdigit():
                continue
            if h not in out:
                out.append(h)
        return out

    # ── scope check ────────────────────────────────────────────────────────────
    def in_scope(self, host: str) -> bool:
        """A host is in scope if it exactly matches, is a subdomain of, or (for a
        CIDR entry) falls inside a listed range."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return True  # nothing to check
        for entry in self.in_scope_hosts:
            entry = entry.rstrip(".")
            if host == entry or host.endswith("." + entry):
                return True
            # CIDR / IP-range entries
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    if ipaddress.ip_address(host) in net:
                        return True
                except ValueError:
                    pass
        return False

    # ── the main entry point ────────────────────────────────────────────────────
    def check_command(self, command: str) -> Decision:
        cmd = (command or "").strip()
        d = Decision(verdict="allow", command=cmd)

        # skip comments / non-commands the model emitted
        if not cmd or cmd.startswith("#"):
            return d

        # 1) forbidden / dangerous RoE patterns
        for pattern, rule, reason in _DANGER_PATTERNS:
            if rule in self.forbid and pattern.search(cmd):
                d.forbidden_hits.append((rule, reason))
                d.reasons.append(f"{rule}: {reason}")

        # 2) scope
        d.targets = self.extract_targets(cmd)
        d.out_of_scope = [h for h in d.targets if not self.in_scope(h)]
        if d.out_of_scope:
            if self.block_out_of_scope:
                d.reasons.append("out-of-scope target(s): " + ", ".join(d.out_of_scope))
            else:
                d.reasons.append(
                    "target(s) not verifiable against scope (no in_scope_hosts set): "
                    + ", ".join(d.out_of_scope))

        # verdict: any forbidden hit blocks; out-of-scope blocks only when we have a
        # scope list to judge against; otherwise warn.
        if d.forbidden_hits or (d.out_of_scope and self.block_out_of_scope):
            d.verdict = "block"
        elif d.out_of_scope:
            d.verdict = "warn"
        return d

    def filter_commands(self, commands: list[str]) -> tuple[list[str], list[Decision]]:
        """Return (safe_commands, decisions). Blocked commands are replaced by their
        annotation so a downstream `| bash` cannot run them, but the operator still
        sees why."""
        safe: list[str] = []
        decisions: list[Decision] = []
        for c in commands or []:
            d = self.check_command(c)
            decisions.append(d)
            if d.verdict == "block":
                safe.append(d.annotation())
            else:
                safe.append(c)
        return safe, decisions


# ── CLI self-test (no Ollama, no network) ─────────────────────────────────────
def _self_test() -> int:
    guard = ScopeGuard(
        in_scope_hosts=["staging.example.com", "10.10.0.0/24"],
        forbid=["dos_or_stress_testing", "bulk_real_pii_exfiltration",
                "out_of_scope_targets"],
    )
    cases = [
        # (command, expected_verdict)
        ("ffuf -w <WORDLIST> -u https://api.staging.example.com/FUZZ -rate 50", "allow"),
        ("nuclei -u https://staging.example.com -rl 20", "allow"),
        ("nmap -sV 10.10.0.5", "allow"),
        ("nmap -sV -T5 --min-rate 50000 prod.example.com", "block"),   # DoS + out-of-scope
        ("sqlmap -u 'https://staging.example.com/x?id=1' --dump-all", "block"),  # bulk PII
        ("sqlmap -u 'https://staging.example.com/x?id=1' --dump -C name --start 1 --stop 1", "allow"),
        ("hydra -l admin -P rockyou.txt staging.example.com http-post-form", "block"),  # no -t
        ("hydra -l admin -P rockyou.txt -t 4 staging.example.com ssh", "allow"),
        ("curl https://prod-admin.example.com/api/users", "block"),    # out-of-scope
        ("# not a tool task: needs manual review", "allow"),
    ]
    ok = True
    for cmd, expect in cases:
        d = guard.check_command(cmd)
        status = "ok" if d.verdict == expect else "FAIL"
        if d.verdict != expect:
            ok = False
        print(f"[{status}] expect={expect:5s} got={d.verdict:5s}  {cmd}")
        if d.reasons:
            print(f"         reasons: {'; '.join(d.reasons)}")
    print(f"\n[{'✓' if ok else '✗'}] scope_guard self-test {'passed' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        raise SystemExit(_self_test())
    if len(sys.argv) >= 2:
        # ad-hoc: scope_guard.py "<command>"  (uses config.yaml if present)
        try:
            import yaml
            from pathlib import Path
            root = Path(__file__).resolve().parent.parent
            cfg = {}
            for name in ("config.yaml", "config.example.yaml"):
                p = root / name
                if p.is_file():
                    cfg = yaml.safe_load(p.read_text()) or {}
                    break
            guard = ScopeGuard.from_config(cfg)
        except Exception:
            guard = ScopeGuard()
        dec = guard.check_command(" ".join(sys.argv[1:]))
        print(f"verdict: {dec.verdict}")
        print(dec.annotation())
        raise SystemExit(0 if dec.allowed else 3)
    print("usage: scope_guard.py --self-test | scope_guard.py \"<command>\"")
