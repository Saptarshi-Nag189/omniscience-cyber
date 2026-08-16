from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from enum import Enum
from pathlib import Path

from .models import Campaign, CampaignStep, CampaignState, StepState


CAMPAIGN_TEMPLATES = {
    'web_recon': {
        'name': 'Web Application Reconnaissance',
        'description': 'Full web app recon: nmap -> nuclei -> ffuf',
        'steps': [
            {
                'id': 'recon_nmap',
                'tool': 'nmap',
                'args': ['-sV', '-T2', '-oX', '-', '{{target}}'],
                'parser': 'nmap_xml',
                'description': 'Service detection on target',
                'timeout': 300,
            },
            {
                'id': 'recon_nuclei',
                'tool': 'nuclei',
                'args': ['-u', '{{target}}', '-json', '-tags', 'cve', '-rl', '20'],
                'parser': 'nuclei_json',
                'description': 'CVE/misconfiguration scan',
                'timeout': 600,
                'depends_on': ['recon_nmap'],
            },
            {
                'id': 'recon_ffuf',
                'tool': 'ffuf',
                'args': ['-u', '{{target}}/FUZZ', '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt', '-of', 'json', '-rate', '50'],
                'parser': 'ffuf_json',
                'description': 'Directory brute force',
                'timeout': 600,
                'depends_on': ['recon_nmap'],
                'condition': 'port 80 in open_ports or port 443 in open_ports',
            },
        ],
    },
    'infra_recon': {
        'name': 'Infrastructure Reconnaissance',
        'description': 'Network/AD recon: nmap -> masscan -> nuclei',
        'steps': [
            {
                'id': 'recon_masscan',
                'tool': 'masscan',
                'args': ['-p1-65535', '--rate', '1000', '-oJ', '-', '{{target}}'],
                'parser': 'masscan_json',
                'description': 'Fast port scan',
                'timeout': 600,
            },
            {
                'id': 'recon_nmap',
                'tool': 'nmap',
                'args': ['-sV', '-T2', '-p', '{{open_ports}}', '-oX', '-', '{{target}}'],
                'parser': 'nmap_xml',
                'description': 'Service detection on open ports',
                'timeout': 300,
                'depends_on': ['recon_masscan'],
            },
            {
                'id': 'recon_nuclei',
                'tool': 'nuclei',
                'args': ['-u', '{{target}}', '-json', '-tags', 'network,cve', '-rl', '20'],
                'parser': 'nuclei_json',
                'description': 'Network CVE scan',
                'timeout': 600,
                'depends_on': ['recon_nmap'],
            },
        ],
    },
    'ad_enum': {
        'name': 'Active Directory Enumeration',
        'description': 'AD enumeration and attack path analysis',
        'steps': [
            {
                'id': 'recon_nmap',
                'tool': 'nmap',
                'args': ['-sV', '-p', '88,135,139,389,445,636,3268,3269,5985', '-oX', '-', '{{target}}'],
                'parser': 'nmap_xml',
                'description': 'AD service detection',
                'timeout': 300,
            },
            {
                'id': 'enum_ldap',
                'tool': 'enum4linux-ng',
                'args': ['-A', '-oJ', '{{target}}'],
                'parser': 'generic',
                'description': 'LDAP enumeration',
                'timeout': 300,
                'depends_on': ['recon_nmap'],
            },
            {
                'id': 'bloodhound',
                'tool': 'bloodhound-python',
                'args': ['-u', '{{username}}', '-p', '{{password}}', '-ns', '{{target}}', '-d', '{{domain}}', '-c', 'All', '--zip'],
                'parser': 'generic',
                'description': 'BloodHound data collection',
                'timeout': 600,
                'depends_on': ['recon_nmap'],
            },
        ],
    },
}


def get_template(name: str) -> Dict:
    return CAMPAIGN_TEMPLATES.get(name, {})


def list_templates() -> List[str]:
    return list(CAMPAIGN_TEMPLATES.keys())


def create_campaign_from_template(template_name: str, target: str, **kwargs) -> Campaign:
    template = get_template(name=template_name)
    if not template:
        raise ValueError(f'Unknown template: {template_name}')
    
    steps = []
    for step_data in template.get('steps', []):
        step = CampaignStep(
            id=step_data['id'],
            tool=step_data['tool'],
            args=step_data['args'],
            parser=step_data['parser'],
            description=step_data.get('description', ''),
            timeout=step_data.get('timeout', 300),
            depends_on=step_data.get('depends_on', []),
            condition=step_data.get('condition', ''),
        )
        steps.append(step)
    
    campaign = Campaign(
        target=kwargs.get('target', ''),
        name=template.get('name', 'Custom Campaign'),
        description=template.get('description', ''),
        steps=steps,
        metadata=kwargs,
    )
    return campaign


def resolve_step_args(step: CampaignStep, context: Dict[str, Any]) -> List[str]:
    return step.render_command(context)


def build_context(campaign: Campaign, step_results: Dict[str, Any]) -> Dict[str, Any]:
    context = {
        'target': campaign.target,
        'open_ports': [],
        'open_web_ports': [],
        'subdomains': [],
        'username': '',
        'password': '',
        'domain': '',
    }
    
    # Merge in metadata
    context.update(campaign.metadata)
    
    # Extract from previous step results
    for step_id, result in step_results.items():
        if hasattr(result, 'parsed_hosts') and result.parsed_hosts:
            for host in result.parsed_hosts:
                for port in host.open_ports():
                    context['open_ports'].append(str(port.number))
                    if port.number in (80, 443, 8080, 8443, 8000, 8888, 9000):
                        context['open_web_ports'].append(str(port.number))
        
        if hasattr(result, 'parsed_findings') and result.parsed_findings:
            for finding in result.parsed_findings:
                if finding.vuln_type == 'subdomain_enumeration':
                    context['subdomains'].append(finding.host)
    
    # Format open_ports as comma-separated string
    if context['open_ports']:
        context['open_ports_str'] = ','.join(set(context['open_ports']))
    
    return context


def check_step_conditions(step: CampaignStep, context: Dict[str, Any]) -> bool:
    if not step.condition:
        return True
    
    condition = step.condition.lower()
    
    if 'port 80 in open_ports' in condition and '80' not in context.get('open_ports', []):
        return False
    if 'port 443 in open_ports' in condition and '443' not in context.get('open_ports', []):
        return False
    
    return True


def get_next_pending_steps(campaign: Campaign, step_results: Dict[str, Any]) -> List[str]:
    context = build_context(campaign, step_results)
    ready = []
    
    for step in campaign.steps:
        if step.state != 'pending':
            continue
        
        # Check dependencies
        deps_met = all(step_results.get(dep_id, {}).get('state') == 'completed' for dep_id in step.depends_on)
        if not deps_met:
            continue
        
        # Check conditions
        if not check_step_conditions(step, context):
            continue
        
        ready.append(step.id)
    
    return ready


def create_campaign(target: str, template: str = 'web_recon', **kwargs) -> Campaign:
    return create_campaign_from_template(template, target, **kwargs)
