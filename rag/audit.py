from __future__ import annotations

"""
rag/audit.py — Cryptographic audit trail with SHA-256 hash chaining for tamper evidence.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS_HASH: str = "0" * 64


class AuditTrail:
    """Audit trail with cryptographic SHA-256 hash chain integrity for tamper evidence."""

    def __init__(self, log_path: str = "audit.log"):
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self._last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the log file, or GENESIS_HASH if empty/missing."""
        if not self.log_path.exists():
            return GENESIS_HASH

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    return GENESIS_HASH
                for line in reversed(lines):
                    line_str = line.strip()
                    if line_str:
                        entry = json.loads(line_str)
                        return entry.get("hash", GENESIS_HASH)
                return GENESIS_HASH
        except Exception:
            return GENESIS_HASH

    def _compute_hash(self, entry: Dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hash of an entry, excluding any existing 'hash' key."""
        clean_entry = {k: v for k, v in entry.items() if k != "hash"}
        canonical_json = json.dumps(clean_entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def log(
        self,
        event: str,
        operator: str = "system",
        campaign_id: str = "",
        step_id: str = "",
        command: str = "",
        verdict: str = "",
        findings_count: int = 0,
        duration: float = 0.0,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Thread-safely log an audit entry into the hash chain and return its SHA-256 hash.
        """
        with self._lock:
            # Prepare entry payload with previous hash link
            entry: Dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operator": operator,
                "campaign_id": campaign_id,
                "step_id": step_id,
                "event": event,
                "command": command,
                "verdict": verdict,
                "findings_count": findings_count,
                "duration": duration,
                "prev_hash": self._last_hash,
            }

            if extra:
                entry["extra"] = extra

            # Compute tamper-evident hash
            entry_hash = self._compute_hash(entry)
            entry["hash"] = entry_hash

            # Ensure parent directory exists before writing
            if self.log_path.parent and not self.log_path.parent.exists():
                self.log_path.parent.mkdir(parents=True, exist_ok=True)

            # Write single line JSON to append log
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")

            self._last_hash = entry_hash
            return entry_hash

    def query(
        self,
        campaign_id: Optional[str] = None,
        event: Optional[str] = None,
        operator: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query audit entries with optional filters, returned most recent first."""
        with self._lock:
            if not self.log_path.exists():
                return []

            entries: List[Dict[str, Any]] = []
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            entry = json.loads(line_str)
                            if campaign_id is not None and entry.get("campaign_id") != campaign_id:
                                continue
                            if event is not None and entry.get("event") != event:
                                continue
                            if operator is not None and entry.get("operator") != operator:
                                continue
                            entries.append(entry)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                return []

        entries.reverse()
        return entries[:limit]

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the cryptographic integrity of the audit log hash chain.
        Returns a dict containing validation status, checked count, and any error details.
        """
        with self._lock:
            if not self.log_path.exists():
                return {"valid": True, "entries_checked": 0, "errors": []}

            errors: List[Dict[str, Any]] = []
            prev_hash = GENESIS_HASH
            entries_checked = 0

            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        line_str = line.strip()
                        if not line_str:
                            continue

                        try:
                            entry = json.loads(line_str)
                        except json.JSONDecodeError as e:
                            errors.append({
                                "line": line_num,
                                "error": f"JSON decode error: {e}",
                            })
                            continue

                        # Verify previous hash link
                        actual_prev_hash = entry.get("prev_hash")
                        if actual_prev_hash != prev_hash:
                            errors.append({
                                "line": line_num,
                                "error": f"Hash chain broken: expected prev_hash '{prev_hash}', got '{actual_prev_hash}'",
                            })

                        # Verify SHA-256 signature
                        expected_hash = entry.get("hash")
                        computed_hash = self._compute_hash(entry)

                        if computed_hash != expected_hash:
                            errors.append({
                                "line": line_num,
                                "error": f"Hash mismatch: expected '{expected_hash}', computed '{computed_hash}'",
                            })

                        prev_hash = expected_hash
                        entries_checked += 1

            except Exception as e:
                errors.append({"line": 0, "error": f"Failed to read audit log: {e}"})

        return {
            "valid": len(errors) == 0,
            "entries_checked": entries_checked,
            "errors": errors,
        }


def create_audit_trail(log_path: str = "audit.log") -> AuditTrail:
    """Convenience factory function to instantiate an AuditTrail."""
    return AuditTrail(log_path)