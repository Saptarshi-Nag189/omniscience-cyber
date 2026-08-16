#!/usr/bin/env python3
from __future__ import annotations

"""
scope_guard.py — Rules-of-Engagement (RoE) enforcement for omniscience-cyber.

The README and config promise "you set the guardrails" (in_scope_hosts, forbid,
require), and verify.py / the test scripts tell the model to "defer to scope_guard".
This module is that guard: a local, offline, dependency-free enforcement layer that
inspects a GENERATED Kali command and decides whether running it stays inside
the engagement's rules of engagement.

It does two things, both LOCAL and deterministic:
  1. SCOPE — extract every host/IP/URL a command targets and check it against the
     engagement's `in_scope_hosts` (including subdomains, wildcards, and CIDR ranges).
  2. RULES OF ENGAGEMENT — scan the command for patterns that map to a `forbid`
     rule (denial-of-service / stress flags, bulk-PII exfiltration like
     `sqlmap --dump-all`, unthrottled brute-force, OS command execution, etc.).

Public API:
  guard = ScopeGuard.from_config(cfg)
  guard.is_in_scope("staging.example.com")     # bool
  decision = guard.check_command("ffuf -u https://api.staging.example.com/FUZZ ...")
  # decision.verdict in {"allow", "warn", "block"}; decision.allowed -> bool
  targets = guard.extract_targets(command)     # list of lowercased target hosts/IPs
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ── Default forbidden rule categories ─────────────────────────────────────────

DEFAULT_FORBIDDEN_RULES: Set[str] = {
    "dos_or_stress_testing",
    "bulk_real_pii_exfiltration",
    "out_of_scope_targets",
    "destructive_commands",
}


# ── Forbidden / dangerous command patterns ────────────────────────────────────

_DANGER_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # ── denial-of-service / stress ────────────────────────────────────────────
    (
        re.compile(r"\bhping3?\b.*(--flood|--faster|-i\s*u\d)", re.I),
        "dos_or_stress_testing",
        "hping flood/stress flags",
    ),
    (
        re.compile(r"\b(slowloris|slowhttptest|t50|mhddos|goldeneye|loic|hoic|xerxes)\b", re.I),
        "dos_or_stress_testing",
        "DoS/stress tool invocation",
    ),
    (
        re.compile(r"\bab\b.*(-n\s*(?:[1-9]\d{3,}|\d{5,})|-c\s*(?:[1-9]\d{2,}|\d{4,}))", re.I),
        "dos_or_stress_testing",
        "ApacheBench with excessive request/concurrency limit",
    ),
    (
        re.compile(r"\bwrk\b.*(-c\s*(?:[1-9]\d{2,}|\d{4,})|-t\s*(?:[5-9]\d|\d{3,}))", re.I),
        "dos_or_stress_testing",
        "wrk with excessive connections/threads",
    ),
    (
        re.compile(r"--flood\b", re.I),
        "dos_or_stress_testing",
        "explicit --flood flag",
    ),
    (
        re.compile(r"\bnmap\b.*(-T5\b|--min-rate\s*(?:[1-9]\d{3,}|\d{5,})|--max-rate\s*(?:[5-9]\d{4,}|\d{6,}))", re.I),
        "dos_or_stress_testing",
        "nmap insane timing (-T5) or high rate limit",
    ),
    (
        re.compile(r"\bmasscan\b.*--rate\s*(?:[5-9]\d{4,}|\d{6,})", re.I),
        "dos_or_stress_testing",
        "masscan dangerously high packet rate (>=50000)",
    ),
    (
        re.compile(r"\bffuf\b.*-rate\s*0\b", re.I),
        "dos_or_stress_testing",
        "ffuf -rate 0 (unlimited request rate)",
    ),

    # ── bulk / unbounded PII exfiltration ─────────────────────────────────────
    (
        re.compile(r"\bsqlmap\b.*--dump-all\b", re.I),
        "bulk_real_pii_exfiltration",
        "sqlmap --dump-all pulls entire databases",
    ),
    (
        re.compile(r"\bsqlmap\b.*(--dump\b(?!.*(--start|--stop|--where|-C\b|--count|--schema|--tables|--columns)))", re.I),
        "bulk_real_pii_exfiltration",
        "sqlmap --dump without bounding flags (--start/--stop/--where/-C)",
    ),
    (
        re.compile(r"\bsqlmap\b.*(--os-shell|--os-cmd|--os-pwn)\b", re.I),
        "bulk_real_pii_exfiltration",
        "sqlmap full OS command execution / shell breakout",
    ),

    # ── unthrottled / aggressive brute force ──────────────────────────────────
    (
        re.compile(r"\bhydra\b(?!.*-t\s*\d)", re.I),
        "dos_or_stress_testing",
        "hydra without a -t task/throttle limit",
    ),
    (
        re.compile(r"\bhydra\b.*-t\s*(?:[6-9]\d|\d{3,})", re.I),
        "dos_or_stress_testing",
        "hydra with excessive task concurrency (-t >= 60)",
    ),
    (
        re.compile(r"\bmedusa\b(?!.*-t\s*\d)", re.I),
        "dos_or_stress_testing",
        "medusa without a -t task concurrency limit",
    ),
    (
        re.compile(r"\bmedusa\b.*-t\s*(?:[6-9]\d|\d{3,})", re.I),
        "dos_or_stress_testing",
        "medusa with excessive task concurrency (-t >= 60)",
    ),

    # ── destructive / wipe commands ───────────────────────────────────────────
    (
        re.compile(r"\b(rm\s+-rf\s+/(?:\s|$)|mkfs\b|dd\s+if=/dev/)", re.I),
        "destructive_commands",
        "destructive disk/system command detected",
    ),
]

# Tokens that clearly are NOT targets even though they look host-ish
_PLACEHOLDER_HOSTS = {
    "<target>",
    "target",
    "example.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}

# File extensions that make a token a filename, NOT a host
_FILE_EXTS = {
    "txt", "lst", "list", "dic", "dict", "py", "sh", "rb", "pl", "php", "js", "ts",
    "json", "yaml", "yml", "xml", "html", "htm", "css", "md", "conf", "cfg", "ini",
    "log", "csv", "tsv", "pdf", "doc", "docx", "xls", "xlsx", "zip", "gz", "tar",
    "tgz", "bz2", "7z", "png", "jpg", "jpeg", "gif", "svg", "pcap", "cap", "pem",
    "key", "crt", "cer", "der", "db", "sqlite", "sqlite3", "bak", "out", "tmp", "env", "so",
}


@dataclass
class Decision:
    """Outcome of inspecting one command."""
    verdict: str                                          # "allow" | "warn" | "block"
    command: str = ""
    targets: List[str] = field(default_factory=list)      # hosts/IPs the command touches
    out_of_scope: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)      # human-readable strings
    forbidden_hits: List[Tuple[str, str]] = field(default_factory=list)  # (rule, reason) tuples

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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "command": self.command,
            "targets": self.targets,
            "out_of_scope": self.out_of_scope,
            "reasons": self.reasons,
            "forbidden_hits": [list(hit) for hit in self.forbidden_hits],
        }


class ScopeGuard:
    """Rules-of-Engagement and scope guardrail engine."""

    def __init__(
        self,
        in_scope_hosts: Optional[Iterable[str]] = None,
        forbid: Optional[Iterable[str]] = None,
        block_out_of_scope: bool = True,
    ):
        self.in_scope_hosts: List[str] = [
            h.strip().lower() for h in (in_scope_hosts or []) if h and h.strip()
        ]
        if forbid is None:
            self.forbid: Set[str] = set(DEFAULT_FORBIDDEN_RULES)
        else:
            self.forbid: Set[str] = {f.strip() for f in forbid if f and f.strip()}

        # If no scope list is configured we warn rather than block on unlisted scope
        self.block_out_of_scope: bool = block_out_of_scope and bool(self.in_scope_hosts)

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]]) -> ScopeGuard:
        g = (cfg or {}).get("guardrails", {}) or {}
        return cls(
            in_scope_hosts=g.get("in_scope_hosts", []),
            forbid=g.get("forbid", None),
            block_out_of_scope=g.get("block_out_of_scope", True),
        )

    # ── Target extraction ─────────────────────────────────────────────────────

    _URL_RE = re.compile(r"https?://([^/\s\"'<>|]+)", re.I)
    _HOST_RE = re.compile(
        r"(?<![\w.-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
        r"|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?![\w.-])"
    )

    def extract_targets(self, command: str) -> List[str]:
        """Best-effort host/IP extraction from a command line. De-duplicated, lowercased."""
        found: List[str] = []
        cmd = command or ""
        for m in self._URL_RE.finditer(cmd):
            host = m.group(1).split("@")[-1].split(":")[0].lower()
            found.append(host)
        for m in self._HOST_RE.finditer(cmd):
            host = m.group(1).split(":")[0].lower()
            found.append(host)

        out: List[str] = []
        for h in found:
            if not h or h in _PLACEHOLDER_HOSTS or h.startswith("<"):
                continue
            # Skip filenames (e.g., wordlists, configs)
            last = h.rsplit(".", 1)[-1]
            if last in _FILE_EXTS and not h.replace(".", "").isdigit():
                continue
            if h not in out:
                out.append(h)
        return out

    # ── Scope checking ────────────────────────────────────────────────────────

    def in_scope(self, host: str) -> bool:
        """
        Check if a host/IP is within in_scope_hosts.
        Supports exact domain match, subdomains, wildcards (*.domain.com), and CIDRs.
        """
        raw_host = (host or "").strip().lower().rstrip(".")
        if not raw_host:
            return True  # nothing to check

        # Strip optional port if passed like "192.168.1.1:8080" or "example.com:443"
        clean_host = raw_host.split(":")[0]

        # If no scope defined, return True (or not restricted)
        if not self.in_scope_hosts:
            return True

        # Try IP check
        host_ip = None
        try:
            host_ip = ipaddress.ip_address(clean_host)
        except ValueError:
            host_ip = None

        for entry in self.in_scope_hosts:
            entry_clean = entry.rstrip(".")

            # Wildcard domain check e.g. *.example.com
            if entry_clean.startswith("*."):
                suffix = entry_clean[1:]  # .example.com
                base = entry_clean[2:]    # example.com
                if clean_host == base or clean_host.endswith(suffix):
                    return True
                continue

            # Standard domain & subdomain check
            if clean_host == entry_clean or clean_host.endswith("." + entry_clean):
                return True

            # CIDR or IP match
            if "/" in entry_clean or (host_ip is not None and not entry_clean.replace(".", "").isalpha()):
                try:
                    net = ipaddress.ip_network(entry_clean, strict=False)
                    if host_ip is not None and host_ip in net:
                        return True
                except ValueError:
                    pass

        return False

    def is_in_scope(self, host: str) -> bool:
        """Helper alias for in_scope."""
        return self.in_scope(host)

    # ── Main check entry point ────────────────────────────────────────────────

    def check_command(self, command: str) -> Decision:
        """Inspect command for forbidden RoE patterns and out-of-scope targets."""
        cmd = (command or "").strip()
        d = Decision(verdict="allow", command=cmd)

        # Skip empty lines or shell comments
        if not cmd or cmd.startswith("#"):
            return d

        # 1) Check dangerous / forbidden RoE patterns
        for pattern, rule, reason in _DANGER_PATTERNS:
            if rule in self.forbid and pattern.search(cmd):
                d.forbidden_hits.append((rule, reason))
                d.reasons.append(f"{rule}: {reason}")

        # 2) Scope check on extracted targets
        d.targets = self.extract_targets(cmd)
        d.out_of_scope = [h for h in d.targets if not self.in_scope(h)]
        if d.out_of_scope:
            if self.block_out_of_scope:
                d.reasons.append("out-of-scope target(s): " + ", ".join(d.out_of_scope))
            else:
                d.reasons.append(
                    "target(s) not verifiable against scope (no in_scope_hosts set): "
                    + ", ".join(d.out_of_scope)
                )

        # Verdict logic:
        # - Any forbidden rule hit blocks.
        # - Out-of-scope target blocks if block_out_of_scope is active; otherwise warns.
        if d.forbidden_hits or (d.out_of_scope and self.block_out_of_scope):
            d.verdict = "block"
        elif d.out_of_scope:
            d.verdict = "warn"

        return d

    def filter_commands(self, commands: List[str]) -> Tuple[List[str], List[Decision]]:
        """
        Return (safe_commands, decisions).
        Blocked commands are replaced by their annotation comment.
        """
        safe: List[str] = []
        decisions: List[Decision] = []
        for c in commands or []:
            d = self.check_command(c)
            decisions.append(d)
            if d.verdict == "block":
                safe.append(d.annotation())
            else:
                safe.append(c)
        return safe, decisions


# ── CLI self-test ─────────────────────────────────────────────────────────────

def _self_test() -> int:
    guard = ScopeGuard(
        in_scope_hosts=["staging.example.com", "10.10.0.0/24", "*.corp.local"],
        forbid=[
            "dos_or_stress_testing",
            "bulk_real_pii_exfiltration",
            "out_of_scope_targets",
            "destructive_commands",
        ],
    )
    cases = [
        ("ffuf -w wordlist.txt -u https://api.staging.example.com/FUZZ -rate 50", "allow"),
        ("nuclei -u https://staging.example.com -rl 20", "allow"),
        ("nmap -sV 10.10.0.5", "allow"),
        ("nmap -sV -T5 --min-rate 50000 staging.example.com", "block"),
        ("sqlmap -u 'https://staging.example.com/x?id=1' --dump-all", "block"),
        ("sqlmap -u 'https://staging.example.com/x?id=1' --dump -C name --start 1 --stop 1", "allow"),
        ("sqlmap -u 'https://staging.example.com/x?id=1' --os-shell", "block"),
        ("hydra -l admin -P rockyou.txt staging.example.com http-post-form", "block"),
        ("hydra -l admin -P rockyou.txt -t 4 staging.example.com ssh", "allow"),
        ("curl https://prod-admin.example.com/api/users", "block"),
        ("curl https://sub.corp.local/test", "allow"),
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
    print(f"\n[{'+' if ok else 'x'}] scope_guard self-test {'passed' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        raise SystemExit(_self_test())
    if len(sys.argv) >= 2:
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
