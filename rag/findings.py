from __future__ import annotations

"""
rag/findings.py — SQLite-backed finding store with deduplication, querying, and reporting statistics.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import Finding, Severity, normalize_severity, utc_now_iso


class FindingStore:
    """SQLite-backed persistent finding store with deduplication hashing and JSON column handling."""

    def __init__(self, db_path: str = "findings.db"):
        self.db_path = Path(db_path)
        if self.db_path.parent and not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    host TEXT,
                    port INTEGER,
                    parameter TEXT,
                    evidence TEXT,
                    cvss_vector TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    cve_ids TEXT,
                    "references" TEXT,
                    tags TEXT,
                    status TEXT DEFAULT 'open',
                    dedup_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign ON findings(campaign_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dedup ON findings(dedup_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_host ON findings(host)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON findings(status)")
            conn.commit()

    def add(self, finding: Finding) -> bool:
        """
        Add a finding to the store. If a finding with identical dedup_hash exists,
        its evidence dictionary is merged and updated_at timestamp updated.
        """
        finding.compute_dedup_hash()
        now = utc_now_iso()

        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT id, evidence, status FROM findings WHERE dedup_hash = ?",
                (finding.dedup_hash,),
            )
            existing = cursor.fetchone()

            if existing:
                existing_evidence: Dict[str, Any] = {}
                try:
                    if existing["evidence"]:
                        existing_evidence = json.loads(existing["evidence"])
                except Exception:
                    existing_evidence = {}

                if isinstance(finding.evidence, dict):
                    existing_evidence.update(finding.evidence)

                conn.execute(
                    """
                    UPDATE findings SET
                        evidence = ?,
                        updated_at = ?,
                        status = ?,
                        cvss_score = ?,
                        cvss_vector = ?,
                        severity = ?
                    WHERE dedup_hash = ?
                    """,
                    (
                        json.dumps(existing_evidence, ensure_ascii=False),
                        now,
                        finding.status or existing["status"],
                        finding.cvss_score,
                        finding.cvss_vector,
                        finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
                        finding.dedup_hash,
                    ),
                )
            else:
                sev_str = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity)
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, campaign_id, step_id, tool, vuln_type, title, description,
                        host, port, parameter, evidence, cvss_vector, cvss_score, severity,
                        cve_ids, "references", tags, status, dedup_hash, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.id,
                        finding.campaign_id,
                        finding.step_id,
                        finding.tool,
                        finding.vuln_type,
                        finding.title,
                        finding.description,
                        finding.host,
                        finding.port,
                        finding.parameter,
                        json.dumps(finding.evidence, ensure_ascii=False),
                        finding.cvss_vector,
                        finding.cvss_score,
                        sev_str,
                        json.dumps(finding.cve_ids, ensure_ascii=False),
                        json.dumps(finding.references, ensure_ascii=False),
                        json.dumps(finding.tags, ensure_ascii=False),
                        finding.status or "open",
                        finding.dedup_hash,
                        finding.created_at or now,
                        finding.updated_at or now,
                    ),
                )
            conn.commit()
        return True

    def get(self, finding_id: str) -> Optional[Finding]:
        """Fetch a single finding by its unique ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def list(
        self,
        campaign_id: Optional[str] = None,
        severity: Optional[Union[str, Severity]] = None,
        status: Optional[str] = None,
        host: Optional[str] = None,
        tool: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Finding]:
        """List findings matching optional query filters."""
        query = 'SELECT * FROM findings WHERE 1=1'
        params: List[Any] = []

        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        if severity:
            sev_val = severity.value if isinstance(severity, Severity) else str(severity).lower()
            query += " AND LOWER(severity) = ?"
            params.append(sev_val)
        if status:
            query += " AND status = ?"
            params.append(status)
        if host:
            query += " AND host = ?"
            params.append(host)
        if tool:
            query += " AND tool = ?"
            params.append(tool)

        query += " ORDER BY updated_at DESC"
        if limit is not None and limit > 0:
            query += f" LIMIT {int(limit)}"

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_finding(row) for row in cursor.fetchall()]

    def update(self, finding: Finding) -> bool:
        """Update an existing finding by ID and refresh deduplication hash and timestamps."""
        finding.compute_dedup_hash()
        finding.updated_at = utc_now_iso()
        sev_str = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity)

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE findings SET
                    campaign_id = ?,
                    step_id = ?,
                    tool = ?,
                    vuln_type = ?,
                    title = ?,
                    description = ?,
                    host = ?,
                    port = ?,
                    parameter = ?,
                    evidence = ?,
                    cvss_vector = ?,
                    cvss_score = ?,
                    severity = ?,
                    cve_ids = ?,
                    "references" = ?,
                    tags = ?,
                    status = ?,
                    dedup_hash = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    finding.campaign_id,
                    finding.step_id,
                    finding.tool,
                    finding.vuln_type,
                    finding.title,
                    finding.description,
                    finding.host,
                    finding.port,
                    finding.parameter,
                    json.dumps(finding.evidence, ensure_ascii=False),
                    finding.cvss_vector,
                    finding.cvss_score,
                    sev_str,
                    json.dumps(finding.cve_ids, ensure_ascii=False),
                    json.dumps(finding.references, ensure_ascii=False),
                    json.dumps(finding.tags, ensure_ascii=False),
                    finding.status,
                    finding.dedup_hash,
                    finding.updated_at,
                    finding.id,
                ),
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete(self, finding_id: str) -> bool:
        """Delete a finding by its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self, campaign_id: Optional[str] = None) -> Dict[str, Any]:
        """Compute aggregate finding statistics (total, by severity, by tool, by status)."""
        where_clause = "WHERE campaign_id = ?" if campaign_id else ""
        params = (campaign_id,) if campaign_id else ()

        with self._get_connection() as conn:
            # Total count
            cursor = conn.execute(f"SELECT COUNT(*) FROM findings {where_clause}", params)
            total = cursor.fetchone()[0]

            # Severity breakdown
            cursor = conn.execute(
                f"SELECT severity, COUNT(*) FROM findings {where_clause} GROUP BY severity",
                params,
            )
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            # Tool breakdown
            cursor = conn.execute(
                f"SELECT tool, COUNT(*) FROM findings {where_clause} GROUP BY tool",
                params,
            )
            by_tool = {row[0]: row[1] for row in cursor.fetchall()}

            # Status breakdown
            cursor = conn.execute(
                f"SELECT status, COUNT(*) FROM findings {where_clause} GROUP BY status",
                params,
            )
            by_status = {row[0]: row[1] for row in cursor.fetchall()}

            return {
                "total": total,
                "by_severity": by_severity,
                "by_tool": by_tool,
                "by_status": by_status,
            }

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        """Helper to safely deserialize a SQLite row into a Finding model."""
        evidence: Dict[str, Any] = {}
        if row["evidence"]:
            try:
                evidence = json.loads(row["evidence"])
            except Exception:
                evidence = {"raw": str(row["evidence"])}

        cve_ids: List[str] = []
        if row["cve_ids"]:
            try:
                cve_ids = json.loads(row["cve_ids"])
            except Exception:
                cve_ids = [str(row["cve_ids"])]

        references: List[str] = []
        if row["references"]:
            try:
                references = json.loads(row["references"])
            except Exception:
                references = [str(row["references"])]

        tags: List[str] = []
        if row["tags"]:
            try:
                tags = json.loads(row["tags"])
            except Exception:
                tags = [str(row["tags"])]

        return Finding(
            id=row["id"],
            campaign_id=row["campaign_id"],
            step_id=row["step_id"],
            tool=row["tool"],
            vuln_type=row["vuln_type"],
            title=row["title"],
            description=row["description"] or "",
            host=row["host"] or "",
            port=row["port"],
            parameter=row["parameter"] or "",
            evidence=evidence,
            cvss_vector=row["cvss_vector"] or "",
            cvss_score=float(row["cvss_score"] or 0.0),
            severity=normalize_severity(row["severity"]),
            cve_ids=cve_ids,
            references=references,
            tags=tags,
            status=row["status"] or "open",
            dedup_hash=row["dedup_hash"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            target=f"{row['host']}:{row['port']}" if (row["host"] and row["port"]) else (row["host"] or ""),
        )


class CampaignFindingManager:
    """Helper manager linking finding operations specifically to a campaign."""

    def __init__(self, store: FindingStore, campaign_id: str):
        self.store = store
        self.campaign_id = campaign_id

    def add_finding(self, finding: Finding) -> bool:
        finding.campaign_id = self.campaign_id
        finding.compute_dedup_hash()
        return self.store.add(finding)

    def get_findings(
        self,
        severity: Optional[Union[str, Severity]] = None,
        status: Optional[str] = None,
    ) -> List[Finding]:
        return self.store.list(campaign_id=self.campaign_id, severity=severity, status=status)

    def get_stats(self) -> Dict[str, Any]:
        return self.store.get_stats(self.campaign_id)

    def get_critical_high(self) -> List[Finding]:
        critical = self.store.list(campaign_id=self.campaign_id, severity="critical")
        high = self.store.list(campaign_id=self.campaign_id, severity="high")
        return critical + high


def create_finding_store(db_path: str = "findings.db") -> FindingStore:
    """Convenience factory function for FindingStore."""
    return FindingStore(db_path)
