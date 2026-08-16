from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Finding, Severity


class FindingStore:
    def __init__(self, db_path: str = "findings.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
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
                    status TEXT DEFAULT "open",
                    dedup_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign ON findings(campaign_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dedup ON findings(dedup_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_host ON findings(host)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)")
            conn.commit()

    def add(self, finding: Finding) -> bool:
        finding.compute_dedup_hash()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT id FROM findings WHERE dedup_hash = ?",
                (finding.dedup_hash,)
            )
            existing = cursor.fetchone()

            if existing:
                conn.execute("""
                    UPDATE findings SET
                        evidence = json_merge(evidence, ?),
                        updated_at = ?,
                        status = ?
                    WHERE dedup_hash = ?
                """, (json.dumps(finding.evidence), datetime.utcnow().isoformat(), finding.status, finding.dedup_hash))
            else:
                conn.execute("""
                    INSERT INTO findings (
                        id, campaign_id, step_id, tool, vuln_type, title, description,
                        host, port, parameter, evidence, cvss_vector, cvss_score, severity,
                        cve_ids, "references", tags, status, dedup_hash, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
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
                    json.dumps(finding.evidence),
                    finding.cvss_vector,
                    finding.cvss_score,
                    finding.severity.value,
                    json.dumps(finding.cve_ids),
                    json.dumps(finding.references),
                    json.dumps(finding.tags),
                    finding.status,
                    finding.dedup_hash,
                    finding.created_at,
                    finding.updated_at,
                ))
            conn.commit()
        return True

    def get(self, finding_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def list(self, campaign_id: str = None, severity: str = None, status: str = None) -> List:
        query = 'SELECT * FROM findings WHERE 1=1'
        params = []

        if campaign_id:
            query += ' AND campaign_id = ?'
            params.append(campaign_id)
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        if status:
            query += ' AND status = ?'
            params.append(status)

        query += ' ORDER BY updated_at DESC'

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [self._row_to_finding(row) for row in cursor.fetchall()]
    def update(self, finding: Finding) -> bool:
        finding.updated_at = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE findings SET
                    title = ?, description = ?, evidence = ?, cvss_vector = ?,
                    cvss_score = ?, severity = ?, cve_ids = ?, "references" = ?,
                    tags = ?, status = ?, updated_at = ?
                WHERE id = ?
            """, (
                finding.title, finding.description, json.dumps(finding.evidence),
                finding.cvss_vector, finding.cvss_score, finding.severity.value,
                json.dumps(finding.cve_ids), json.dumps(finding.references),
                json.dumps(finding.tags), finding.status, finding.updated_at,
                finding.id
            ))
            conn.commit()
        return True

    def delete(self, finding_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            conn.commit()
            return True

    def get_stats(self, campaign_id: str) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings WHERE campaign_id = ?
                GROUP BY severity
            """, (campaign_id,))
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor = conn.execute("SELECT COUNT(*) FROM findings WHERE campaign_id = ?", (campaign_id,))
            total = cursor.fetchone()[0]

            return {
                "total": total,
                "by_severity": severity_counts,
            }

    def _row_to_finding(self, row) -> Finding:
        return Finding(
            id=row["id"],
            campaign_id=row["campaign_id"],
            step_id=row["step_id"],
            tool=row["tool"],
            vuln_type=row["vuln_type"],
            title=row["title"],
            description=row["description"],
            host=row["host"],
            port=row["port"],
            parameter=row["parameter"],
            evidence=json.loads(row["evidence"]) if row["evidence"] else {},
            cvss_vector=row["cvss_vector"],
            cvss_score=row["cvss_score"],
            severity=Severity(row["severity"]),
            cve_ids=json.loads(row["cve_ids"]) if row["cve_ids"] else [],
            references=json.loads(row["references"]) if row["references"] else [],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            status=row["status"],
            dedup_hash=row["dedup_hash"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class CampaignFindingManager:
    def __init__(self, store, campaign_id: str):
        self.store = store
        self.campaign_id = campaign_id

    def add_finding(self, finding: Finding) -> bool:
        finding.campaign_id = self.campaign_id
        finding.compute_dedup_hash()
        return self.store.add(finding)

    def get_findings(self, severity: str = None, status: str = None):
        return self.store.list(campaign_id=self.campaign_id, severity=severity, status=status)

    def get_stats(self) -> Dict:
        return self.store.get_stats(self.campaign_id)

    def get_critical_high(self) -> List:
        critical = self.store.list(campaign_id=self.campaign_id, severity="critical")
        high = self.store.list(campaign_id=self.campaign_id, severity="high")
        return critical + high


def create_finding_store(db_path: str = "findings.db"):
    return FindingStore(db_path)
