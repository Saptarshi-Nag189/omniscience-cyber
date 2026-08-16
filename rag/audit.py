from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditTrail:
    """Audit trail with hash chain integrity for tamper evidence."""
    
    def __init__(self, log_path: str = "audit.log"):
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self._last_hash = self._get_last_hash()
    
    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the log."""
        if not self.log_path.exists():
            return "0" * 64
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if not lines:
                    return "0" * 64
                last_line = lines[-1].strip()
                if not last_line:
                    return "0" * 64
                entry = json.loads(last_line)
                return entry.get("hash", "0" * 64)
        except Exception:
            return "0" * 64
    
    def _compute_hash(self, entry: Dict[str, Any]) -> str:
        """Compute SHA256 hash of an entry."""
        content = json.dumps(entry, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(content.encode()).hexdigest()
    
    def log(self, event: str, operator: str, campaign_id: str = "", step_id: str = "",
            command: str = "", verdict: str = "", findings_count: int = 0,
            duration: float = 0.0, extra: Optional[Dict[str, Any]] = None) -> str:
        """Log an audit entry and return its hash."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
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
        
        entry["hash"] = self._compute_hash(entry)
        
        with self._lock:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, separators=(',', ':')) + '\n')
            self._last_hash = entry["hash"]
        
        return entry["hash"]
    
    def query(self, campaign_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit entries, optionally filtered by campaign_id."""
        if not self.log_path.exists():
            return []
        
        entries = []
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if campaign_id is None or entry.get("campaign_id") == campaign_id:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue
        
        # Return most recent first
        entries.reverse()
        return entries[:limit]
    
    def verify_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the hash chain."""
        if not self.log_path.exists():
            return {"valid": True, "entries_checked": 0, "errors": []}
        
        errors = []
        prev_hash = "0" * 64
        entries_checked = 0
        
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    
                    # Check prev_hash matches
                    if entry.get("prev_hash") != prev_hash:
                        errors.append({
                            "line": line_num,
                            "error": f"Hash chain broken: expected prev_hash {prev_hash}, got {entry.get('prev_hash')}"
                        })
                    
                    # Verify hash
                    expected_hash = entry.get("hash")
                    # Recompute hash without the hash field
                    entry_copy = {k: v for k, v in entry.items() if k != "hash"}
                    computed_hash = hashlib.sha256(
                        json.dumps(entry_copy, sort_keys=True, separators=(',', ':')).encode()
                    ).hexdigest()
                    
                    if computed_hash != expected_hash:
                        errors.append({
                            "line": line_num,
                            "error": f"Hash mismatch: expected {expected_hash}, computed {computed_hash}"
                        })
                    
                    prev_hash = expected_hash
                    entries_checked += 1
                    
                except json.JSONDecodeError as e:
                    errors.append({
                        "line": line_num,
                        "error": f"JSON decode error: {e}"
                    })
        
        return {
            "valid": len(errors) == 0,
            "entries_checked": entries_checked,
            "errors": errors
        }


# Convenience function for creating audit trail
def create_audit_trail(log_path: str = "audit.log") -> AuditTrail:
    return AuditTrail(log_path)