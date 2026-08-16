from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Finding, Campaign, Severity
from .findings import FindingStore


class ReportGenerator:
    def __init__(self, store: FindingStore):
        self.store = store
    
    def generate_markdown(self, campaign_id: str) -> str:
        """Generate a Markdown report for a campaign."""
        findings = self.store.list(campaign_id=campaign_id)
        stats = self.store.get_stats(campaign_id)
        
        lines = []
        lines.append(f'# Penetration Test Report')
        lines.append(f'')
        lines.append(f'**Campaign ID:** {campaign_id}')
        lines.append(f'**Generated:** {datetime.utcnow().isoformat()}Z')
        lines.append(f'')
        
        # Executive Summary
        lines.append(f'## Executive Summary')
        lines.append(f'')
        lines.append(f'- **Total Findings:** {stats.get("total", 0)}')
        for sev, count in stats.get("by_severity", {}).items():
            lines.append(f'- **{sev.capitalize()}:** {count}')
        lines.append(f'')
        
        # Findings
        lines.append(f'## Findings')
        lines.append(f'')
        
        if not findings:
            lines.append(f'No findings reported.')
        else:
            # Group by severity
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            for sev in severity_order:
                sev_findings = [f for f in findings if f.severity.value == sev]
                if not sev_findings:
                    continue
                lines.append(f'### {sev.capitalize()} Severity ({len(sev_findings)} findings)')
                lines.append(f'')
                for finding in sev_findings:
                    lines.append(f'#### {finding.title}')
                    lines.append(f'')
                    lines.append(f'- **ID:** {finding.id}')
                    lines.append(f'- **Type:** {finding.vuln_type}')
                    lines.append(f'- **Host:** {finding.host}')
                    if finding.port:
                        lines.append(f'- **Port:** {finding.port}')
                    lines.append(f'- **Parameter:** {finding.parameter}')
                    lines.append(f'- **Tool:** {finding.tool}')
                    lines.append(f'- **CVSS:** {finding.cvss_vector} ({finding.cvss_score})')
                    lines.append(f'- **Status:** {finding.status}')
                    lines.append(f'')
                    lines.append(f'{finding.description}')
                    lines.append(f'')
                    if finding.evidence:
                        lines.append(f'**Evidence:**')
                        lines.append(f'```json')
                        lines.append(f'{json.dumps(finding.evidence, indent=2)}')
                        lines.append(f'```')
                        lines.append(f'')
                    if finding.cve_ids:
                        lines.append(f'- **CVE IDs:** {", ".join(finding.cve_ids)}')
                        lines.append(f'')
                    if finding.references:
                        lines.append(f'- **References:**')
                        for ref in finding.references:
                            lines.append(f'- {ref}')
                            lines.append(f'')
        
        return '\n'.join(lines)
    
    def export_findings_json(self, campaign_id: str) -> str:
        """Export findings as JSON."""
        findings = self.store.list(campaign_id=campaign_id)
        data = {
            'campaign_id': campaign_id,
            'generated_at': datetime.utcnow().isoformat(),
            'findings': [f.to_dict() for f in findings]
        }
        return json.dumps(data, indent=2)


def create_report_generator(store: FindingStore) -> ReportGenerator:
    return ReportGenerator(store)