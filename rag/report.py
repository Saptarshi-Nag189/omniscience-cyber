from __future__ import annotations

"""
rag/report.py — Report generator for omniscience-cyber security campaigns.
Produces professional Markdown assessments and structured JSON exports.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .findings import FindingStore
from .models import Campaign, Finding, Severity, normalize_severity, utc_now_iso


class ReportGenerator:
    """Generates Markdown and JSON penetration test and vulnerability assessment reports."""

    def __init__(self, store: Optional[FindingStore] = None):
        self.store = store

    def _get_findings_and_stats(
        self, campaign_id: Optional[str] = None, campaign: Optional[Campaign] = None
    ) -> tuple[List[Finding], Dict[str, Any], str, str]:
        """Resolve findings, stats, target, and campaign name from store or campaign object."""
        target_name = "Target"
        campaign_name = "Security Assessment"
        cid = campaign_id or ""

        if campaign:
            cid = campaign.id
            target_name = campaign.target or target_name
            campaign_name = campaign.name or campaign_name
            findings = list(campaign.findings)

            # Compute stats from campaign findings
            by_severity: Dict[str, int] = {}
            for f in findings:
                sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1
            stats = {
                "total": len(findings),
                "by_severity": by_severity,
            }
        elif self.store and cid:
            findings = self.store.list(campaign_id=cid)
            stats = self.store.get_stats(cid)
            if findings:
                target_name = findings[0].host or target_name
        elif self.store:
            findings = self.store.list()
            stats = self.store.get_stats()
        else:
            findings = []
            stats = {"total": 0, "by_severity": {}}

        return findings, stats, cid, target_name

    def generate_markdown(
        self,
        campaign_id: Optional[str] = None,
        campaign: Optional[Campaign] = None,
    ) -> str:
        """Generate a comprehensive Markdown penetration testing assessment report."""
        findings, stats, cid, target_name = self._get_findings_and_stats(campaign_id, campaign)
        generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: List[str] = []
        lines.append("# Security Assessment Report")
        lines.append("")
        if cid:
            lines.append(f"**Campaign ID:** `{cid}`  ")
        if target_name:
            lines.append(f"**Target:** `{target_name}`  ")
        lines.append(f"**Generated At:** {generated_time}  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        total_findings = stats.get("total", len(findings))
        by_sev = stats.get("by_severity", {})

        crit_count = by_sev.get("critical", 0)
        high_count = by_sev.get("high", 0)
        med_count = by_sev.get("medium", 0)
        low_count = by_sev.get("low", 0)
        info_count = by_sev.get("info", 0)

        lines.append(f"A total of **{total_findings}** finding(s) were identified during the assessment:")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("| :--- | :--- |")
        lines.append(f"| 🔴 **Critical** | {crit_count} |")
        lines.append(f"| 🟠 **High** | {high_count} |")
        lines.append(f"| 🟡 **Medium** | {med_count} |")
        lines.append(f"| 🔵 **Low** | {low_count} |")
        lines.append(f"| ⚪ **Info** | {info_count} |")
        lines.append(f"| **Total** | **{total_findings}** |")
        lines.append("")

        # Findings Summary Table
        lines.append("## 2. Findings Overview")
        lines.append("")
        if not findings:
            lines.append("No security vulnerabilities or findings were identified.")
            lines.append("")
        else:
            lines.append("| ID | Severity | Title | Host / Target | Tool |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in findings:
                sev_label = f.severity.value.upper() if isinstance(f.severity, Severity) else str(f.severity).upper()
                host_target = f"{f.host}:{f.port}" if (f.host and f.port) else (f.host or f.target or "-")
                lines.append(f"| `{f.id}` | {sev_label} | {f.title} | `{host_target}` | {f.tool} |")
            lines.append("")

        # Detailed Findings Section
        lines.append("## 3. Detailed Vulnerability Findings")
        lines.append("")
        if not findings:
            lines.append("No detailed findings to report.")
            lines.append("")
        else:
            severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
            for sev in severity_order:
                sev_findings = [
                    f for f in findings
                    if (f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()) == sev
                ]
                if not sev_findings:
                    continue

                lines.append(f"### {sev.capitalize()} Severity ({len(sev_findings)})")
                lines.append("")

                for f in sev_findings:
                    lines.append(f"#### {f.title}")
                    lines.append("")
                    lines.append(f"- **Finding ID:** `{f.id}`")
                    lines.append(f"- **Vulnerability Type:** {f.vuln_type or f.title}")
                    lines.append(f"- **Host / Target:** `{f.host or f.target}`" + (f" (Port {f.port})" if f.port else ""))
                    if f.parameter:
                        lines.append(f"- **Affected Parameter:** `{f.parameter}`")
                    lines.append(f"- **Tool:** {f.tool}")
                    if f.cvss_vector or f.cvss_score > 0:
                        lines.append(f"- **CVSS:** {f.cvss_vector} (Score: {f.cvss_score})")
                    lines.append(f"- **Status:** `{f.status}`")
                    lines.append("")
                    if f.description:
                        lines.append("**Description:**")
                        lines.append(f"{f.description}")
                        lines.append("")

                    if f.evidence:
                        lines.append("**Evidence / Reproduction:**")
                        lines.append("```json")
                        lines.append(json.dumps(f.evidence, indent=2, ensure_ascii=False))
                        lines.append("```")
                        lines.append("")

                    if f.cve_ids:
                        lines.append(f"**Associated CVEs:** {', '.join(f.cve_ids)}")
                        lines.append("")

                    if f.references:
                        lines.append("**References:**")
                        for ref in f.references:
                            lines.append(f"- <{ref}>" if ref.startswith("http") else f"- {ref}")
                        lines.append("")
                    lines.append("---")
                    lines.append("")

        return "\n".join(lines)

    def export_findings_json(
        self,
        campaign_id: Optional[str] = None,
        campaign: Optional[Campaign] = None,
        indent: int = 2,
    ) -> str:
        """Export campaign findings as structured JSON."""
        findings, stats, cid, target_name = self._get_findings_and_stats(campaign_id, campaign)
        data = {
            "campaign_id": cid,
            "target": target_name,
            "generated_at": utc_now_iso(),
            "stats": stats,
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(data, indent=indent, ensure_ascii=False)


def create_report_generator(store: Optional[FindingStore] = None) -> ReportGenerator:
    """Factory helper to instantiate a ReportGenerator."""
    return ReportGenerator(store)