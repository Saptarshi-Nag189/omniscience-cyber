# Append the rest of findings.py
import os

f = open('C:/temp/omniscience-cyber/rag/findings.py', 'a', encoding='utf-8')

f.write('''
    def update(self, finding: Finding) -> bool:
        finding.updated_at = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE findings SET
                    title = ?, description = ?, evidence = ?, cvss_vector = ?,
                    cvss_score = ?, severity = ?, cve_ids = ?, references = ?,
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
''')

print("findings.py completed")