from __future__ import annotations

"""
rag/planner.py — Campaign template loading, DAG dependency resolution, and step planning.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import yaml
except ImportError:
    yaml = None

from .models import Campaign, CampaignStep, CampaignState, StepState, Host, Finding, Port


# Built-in campaign templates (used as fallback or defaults)
CAMPAIGN_TEMPLATES: Dict[str, Dict[str, Any]] = {
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

WEB_PORT_NUMBERS = {80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 3000, 4000, 5000, 8081, 8444}


def find_template_dirs() -> List[Path]:
    """Find candidate template directories in order of priority."""
    dirs: List[Path] = []
    
    env_dir = os.environ.get("CAMPAIGN_TEMPLATES_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            dirs.append(p)

    repo_templates = Path(__file__).resolve().parent.parent / "templates"
    if repo_templates.is_dir() and repo_templates not in dirs:
        dirs.append(repo_templates)

    local_templates = Path(__file__).resolve().parent / "templates"
    if local_templates.is_dir() and local_templates not in dirs:
        dirs.append(local_templates)

    cwd_templates = Path.cwd() / "templates"
    if cwd_templates.is_dir() and cwd_templates not in dirs:
        dirs.append(cwd_templates)

    return dirs


def load_templates(template_dir: Optional[Union[str, Path]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Discover and load all *.yaml and *.yml template files from the templates directory.
    Falls back gracefully to built-in CAMPAIGN_TEMPLATES.
    """
    # Start with built-in templates
    templates: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in CAMPAIGN_TEMPLATES.items()}

    search_dirs = [Path(template_dir)] if template_dir and Path(template_dir).is_dir() else find_template_dirs()

    if yaml is not None:
        for t_dir in search_dirs:
            if not t_dir.exists():
                continue
            for ext in ("*.yaml", "*.yml"):
                for yaml_path in sorted(t_dir.glob(ext)):
                    try:
                        with open(yaml_path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                        if isinstance(data, dict) and "steps" in data:
                            template_id = yaml_path.stem
                            templates[template_id] = data
                    except Exception:
                        continue

    return templates


def get_template(name: str, template_dir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Retrieve template definition by name/id or display name."""
    templates = load_templates(template_dir)
    if name in templates:
        return templates[name]

    # Try case-insensitive lookup by key or by display name
    name_lower = name.lower()
    for k, v in templates.items():
        if k.lower() == name_lower:
            return v
        if isinstance(v, dict) and v.get('name', '').lower() == name_lower:
            return v

    return {}


def list_templates(template_dir: Optional[Union[str, Path]] = None) -> List[str]:
    """Return sorted list of available template identifiers."""
    templates = load_templates(template_dir)
    return sorted(list(templates.keys()))


def create_campaign_from_template(template_name: str, target: str = "", **kwargs) -> Campaign:
    """Create a Campaign instance instantiated from a template."""
    template = get_template(name=template_name)
    if not template:
        raise ValueError(f"Unknown template: {template_name}")

    resolved_target = target or kwargs.get("target", "")

    steps = []
    for step_data in template.get("steps", []):
        step = CampaignStep(
            id=step_data["id"],
            tool=step_data.get("tool", ""),
            args=list(step_data.get("args", [])),
            command=step_data.get("command", ""),
            parser=step_data.get("parser", ""),
            description=step_data.get("description", ""),
            timeout=step_data.get("timeout", 300),
            depends_on=list(step_data.get("depends_on", [])),
            condition=step_data.get("condition", ""),
            target=resolved_target,
        )
        steps.append(step)

    campaign = Campaign(
        target=resolved_target,
        name=template.get("name", "Custom Campaign"),
        description=template.get("description", ""),
        steps=steps,
        metadata=dict(kwargs),
    )
    return campaign


def create_campaign(target: str, template: str = "web_recon", **kwargs) -> Campaign:
    """Convenience factory to create a campaign for a given target and template."""
    return create_campaign_from_template(template, target, **kwargs)


def _extract_ports_from_host(host: Any) -> Tuple[List[str], List[str]]:
    """Extract open port strings and open web port strings from a Host object or dict."""
    open_ports: List[str] = []
    web_ports: List[str] = []

    if hasattr(host, "open_ports") and callable(host.open_ports):
        for port in host.open_ports():
            p_num = getattr(port, "number", getattr(port, "port", None))
            if p_num is not None:
                p_str = str(p_num)
                open_ports.append(p_str)
                try:
                    if int(p_num) in WEB_PORT_NUMBERS:
                        web_ports.append(p_str)
                except (ValueError, TypeError):
                    pass
    elif hasattr(host, "ports") and isinstance(host.ports, list):
        for port in host.ports:
            state = getattr(port, "state", "")
            if state == "open" or not state:
                p_num = getattr(port, "number", getattr(port, "port", None))
                if p_num is not None:
                    p_str = str(p_num)
                    open_ports.append(p_str)
                    try:
                        if int(p_num) in WEB_PORT_NUMBERS:
                            web_ports.append(p_str)
                    except (ValueError, TypeError):
                        pass
    elif isinstance(host, dict):
        raw_ports = host.get("ports", []) or host.get("open_ports", [])
        for p in raw_ports:
            if isinstance(p, dict):
                if p.get("state", "open") == "open":
                    num = p.get("number", p.get("port"))
                    if num is not None:
                        p_str = str(num)
                        open_ports.append(p_str)
                        try:
                            if int(num) in WEB_PORT_NUMBERS:
                                web_ports.append(p_str)
                        except (ValueError, TypeError):
                            pass
            elif isinstance(p, (int, str)):
                p_str = str(p)
                open_ports.append(p_str)
                try:
                    if int(p) in WEB_PORT_NUMBERS:
                        web_ports.append(p_str)
                except (ValueError, TypeError):
                    pass

    return open_ports, web_ports


def _extract_from_finding(finding: Any, context: Dict[str, Any]) -> None:
    """Extract open ports and subdomains from a Finding object or dict."""
    if isinstance(finding, dict):
        vuln_type = str(finding.get("vuln_type", finding.get("title", ""))).lower()
        host = str(finding.get("host", finding.get("target", "")))
        port = finding.get("port")
        evidence = finding.get("evidence", {})
    else:
        vuln_type = str(getattr(finding, "vuln_type", getattr(finding, "title", ""))).lower()
        host = str(getattr(finding, "host", getattr(finding, "target", "")))
        port = getattr(finding, "port", None)
        evidence = getattr(finding, "evidence", {})

    if port:
        p_str = str(port)
        if p_str not in context["open_ports"]:
            context["open_ports"].append(p_str)
        try:
            if int(port) in WEB_PORT_NUMBERS and p_str not in context["open_web_ports"]:
                context["open_web_ports"].append(p_str)
        except (ValueError, TypeError):
            pass

    # Subdomain discovery heuristics
    if any(sub_kw in vuln_type for sub_kw in ("subdomain", "dns", "asset", "vhost", "zone_transfer")):
        if host and host not in context["subdomains"]:
            context["subdomains"].append(host)

    if isinstance(evidence, dict):
        if "subdomains" in evidence and isinstance(evidence["subdomains"], list):
            for sub in evidence["subdomains"]:
                s_str = str(sub)
                if s_str and s_str not in context["subdomains"]:
                    context["subdomains"].append(s_str)
        if "hosts" in evidence and isinstance(evidence["hosts"], list):
            for h in evidence["hosts"]:
                h_str = str(h)
                if h_str and h_str not in context["subdomains"]:
                    context["subdomains"].append(h_str)


def build_context(campaign: Optional[Campaign], step_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build unified execution context from campaign metadata and step results.
    Populates open_ports, open_ports_str, open_web_ports, subdomains, target, username, password, domain.
    """
    context: Dict[str, Any] = {
        'target': campaign.target if campaign else '',
        'open_ports': [],
        'open_ports_str': '',
        'open_web_ports': [],
        'subdomains': [],
        'username': '',
        'password': '',
        'domain': '',
    }

    # Merge campaign metadata
    if campaign and hasattr(campaign, 'metadata') and isinstance(campaign.metadata, dict):
        context.update(campaign.metadata)

    if campaign and campaign.target:
        context['target'] = campaign.target

    for step_id, result in (step_results or {}).items():
        if result is None:
            continue

        res_obj = getattr(result, "result", result)
        if res_obj is None:
            res_obj = result

        # 1. Hosts
        hosts = []
        if hasattr(res_obj, "parsed_hosts") and res_obj.parsed_hosts:
            hosts.extend(res_obj.parsed_hosts)
        elif hasattr(res_obj, "hosts") and res_obj.hosts:
            hosts.extend(res_obj.hosts)
        elif isinstance(res_obj, dict):
            hosts.extend(res_obj.get("parsed_hosts", []) or res_obj.get("hosts", []))

        for host in hosts:
            o_ports, w_ports = _extract_ports_from_host(host)
            for p in o_ports:
                if p not in context['open_ports']:
                    context['open_ports'].append(p)
            for p in w_ports:
                if p not in context['open_web_ports']:
                    context['open_web_ports'].append(p)

        # 2. Findings / Vulnerabilities
        findings = []
        if hasattr(res_obj, "parsed_findings") and res_obj.parsed_findings:
            findings.extend(res_obj.parsed_findings)
        elif hasattr(res_obj, "findings") and res_obj.findings:
            findings.extend(res_obj.findings)
        elif hasattr(res_obj, "vulnerabilities") and res_obj.vulnerabilities:
            findings.extend(res_obj.vulnerabilities)
        elif isinstance(res_obj, dict):
            findings.extend(
                res_obj.get("parsed_findings", [])
                or res_obj.get("findings", [])
                or res_obj.get("vulnerabilities", [])
            )

        for finding in findings:
            _extract_from_finding(finding, context)

        # 3. Direct dictionary / metadata attributes
        if isinstance(res_obj, dict):
            if "open_ports" in res_obj and isinstance(res_obj["open_ports"], list):
                for p in res_obj["open_ports"]:
                    p_str = str(p)
                    if p_str not in context['open_ports']:
                        context['open_ports'].append(p_str)
            if "open_web_ports" in res_obj and isinstance(res_obj["open_web_ports"], list):
                for p in res_obj["open_web_ports"]:
                    p_str = str(p)
                    if p_str not in context['open_web_ports']:
                        context['open_web_ports'].append(p_str)
            if "subdomains" in res_obj and isinstance(res_obj["subdomains"], list):
                for s in res_obj["subdomains"]:
                    s_str = str(s)
                    if s_str not in context['subdomains']:
                        context['subdomains'].append(s_str)
            for key in ("username", "password", "domain", "target"):
                if key in res_obj and res_obj[key] and not context.get(key):
                    context[key] = str(res_obj[key])

    # Format open_ports_str
    if context['open_ports']:
        sorted_ports = sorted(
            list(set(context['open_ports'])),
            key=lambda x: int(x) if str(x).isdigit() else str(x)
        )
        context['open_ports_str'] = ','.join(sorted_ports)
    else:
        context['open_ports_str'] = ''

    return context


class FlexibleContainer(list):
    """List container supporting flexible membership check for both integer and string tokens."""
    def __init__(self, items=None):
        super().__init__(items or [])
        self._set = set()
        for item in (items or []):
            self._set.add(str(item))
            try:
                self._set.add(int(item))
            except (ValueError, TypeError):
                pass

    def __contains__(self, item: Any) -> bool:
        if item in self._set:
            return True
        if str(item) in self._set:
            return True
        try:
            if int(item) in self._set:
                return True
        except (ValueError, TypeError):
            pass
        return False


def _normalize_condition(expr: str) -> str:
    """Normalize condition string into valid Python expression syntax."""
    s = expr.strip()
    s = re.sub(r'\bport\s+(\d+)\b', r"'\1'", s, flags=re.IGNORECASE)
    s = re.sub(r'\bhas_port\(\s*[\'"]?(\d+)[\'"]?\s*\)', r"'\1' in open_ports", s, flags=re.IGNORECASE)
    return s


def check_step_conditions(step: CampaignStep, context: Dict[str, Any]) -> bool:
    """
    Evaluate step condition expressions.
    Supports complex conditions e.g. 'port 80 in open_ports or port 443 in open_ports'.
    """
    if not step or not step.condition or not step.condition.strip():
        return True

    cond_raw = step.condition.strip()
    cond_norm = _normalize_condition(cond_raw)

    open_ports = FlexibleContainer(context.get('open_ports', []))
    open_web_ports = FlexibleContainer(context.get('open_web_ports', []))
    subdomains = list(context.get('subdomains', []))

    eval_env = {
        'open_ports': open_ports,
        'open_ports_str': context.get('open_ports_str', ''),
        'open_web_ports': open_web_ports,
        'subdomains': subdomains,
        'target': context.get('target', ''),
        'username': context.get('username', ''),
        'password': context.get('password', ''),
        'domain': context.get('domain', ''),
        'len': len,
        'str': str,
        'int': int,
        'bool': bool,
        'any': any,
        'all': all,
    }

    for k, v in context.items():
        if k not in eval_env:
            eval_env[k] = v

    try:
        res = eval(cond_norm, {"__builtins__": {}}, eval_env)
        return bool(res)
    except Exception:
        # Fallback to pattern matching
        cond_lower = cond_raw.lower()
        if 'port 80 in open_ports' in cond_lower or "'80' in open_ports" in cond_lower:
            if '80' in open_ports:
                return True
        if 'port 443 in open_ports' in cond_lower or "'443' in open_ports" in cond_lower:
            if '443' in open_ports:
                return True
        if 'or' in cond_lower:
            parts = [p.strip() for p in cond_lower.split('or')]
            for p in parts:
                m = re.search(r'port\s+(\d+)\s+in\s+open_ports', p)
                if m and m.group(1) in open_ports:
                    return True
        return False


def _is_step_completed(res: Any) -> bool:
    """Check if a step result indicates completion."""
    if res is None:
        return False
    if isinstance(res, bool):
        return res
    if isinstance(res, dict):
        st = str(res.get("state", res.get("status", ""))).lower()
        if st in ("completed", "success", "done", "passed"):
            return True
        if res.get("success") is True:
            return True
        if ("parsed_hosts" in res or "parsed_findings" in res or "raw_output" in res) and not res.get("error") and res.get("success") is not False:
            return True
        return False
    if hasattr(res, "state"):
        st = res.state.value if isinstance(res.state, StepState) else str(res.state)
        if st.lower() in ("completed", "success", "done"):
            return True
    if hasattr(res, "success"):
        if res.success:
            return True
    if hasattr(res, "completed_at") and res.completed_at:
        return True
    return False


def get_next_pending_steps(campaign: Campaign, step_results: Dict[str, Any]) -> List[str]:
    """
    Return ready step IDs whose depends_on dependencies are satisfied and conditions evaluate to True.
    """
    context = build_context(campaign, step_results)
    ready: List[str] = []

    # Build set of completed step IDs
    completed_steps: Set[str] = set()
    for step_id, res in (step_results or {}).items():
        if _is_step_completed(res):
            completed_steps.add(step_id)

    for step in campaign.steps:
        st = step.state.value if isinstance(step.state, StepState) else str(step.state)
        if st.lower() == "completed":
            completed_steps.add(step.id)

    for step in campaign.steps:
        st = step.state.value if isinstance(step.state, StepState) else str(step.state)
        if st.lower() != "pending":
            continue

        # If already completed in step_results, skip
        if step.id in completed_steps:
            continue

        # Check dependencies
        if step.depends_on:
            deps_met = all(dep_id in completed_steps for dep_id in step.depends_on)
            if not deps_met:
                continue

        # Check conditions
        if not check_step_conditions(step, context):
            continue

        ready.append(step.id)

    return ready


def resolve_step_args(step: CampaignStep, context: Dict[str, Any]) -> List[str]:
    """
    Render template arguments with unified context.
    Formats open_ports and open_web_ports as comma-separated lists for CLI tool args.
    """
    render_ctx = dict(context)
    if isinstance(render_ctx.get("open_ports"), list):
        render_ctx["open_ports"] = render_ctx.get("open_ports_str") or ",".join(str(p) for p in render_ctx["open_ports"])
    if isinstance(render_ctx.get("open_web_ports"), list):
        render_ctx["open_web_ports"] = ",".join(str(p) for p in render_ctx["open_web_ports"])
    return step.render_command(render_ctx)
