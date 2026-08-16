from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .models import Finding, Host, Port, ScanResult, Severity, Service

def parse_nmap_xml(xml_str: str):
    hosts = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        return [Host(address='', extra={'parse_error': str(e)})]
    for host_elem in root.findall('host'):
        addr_elem = host_elem.find('address')
        address = addr_elem.get('addr', '') if addr_elem is not None else ''
        hostnames = []
        for hn in host_elem.findall('hostnames/hostname'):
            hostnames.append(hn.get('name', ''))
        ports = []
        for port_elem in root.findall('ports/port'):
            port_id = int(port_elem.get('portid', '0'))
            protocol = port_elem.get('protocol', 'tcp')
            state_elem = port_elem.find('state')
            state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'
            service_elem = port_elem.find('service')
            service = None
            if service_elem is not None:
                service = Service(
                    name=service_elem.get('name', ''),
                    product=service_elem.get('product', ''),
                    version=service_elem.get('version', ''),
                    extrainfo=service_elem.get('extrainfo', ''),
                    cpe=[cpe.text for cpe in service_elem.findall('cpe') if cpe.text],
                )
            scripts = []
            for script in port_elem.findall('script'):
                scripts.append({'id': script.get('id', ''), 'output': script.get('output', '')})
            ports.append(Port(number=port_id, protocol=protocol, state=state, service=service, scripts=scripts))
        os_match = None
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                os_match = {'name': osmatch.get('name', ''), 'accuracy': osmatch.get('accuracy', '')}
        distance = None
        dist_elem = host_elem.find('distance')
        if dist_elem is not None:
            distance = int(dist_elem.get('value', '0'))
        hosts.append(Host(address=address, hostnames=hostnames, ports=ports, os=os_match, distance=distance))
    return hosts


def parse_nuclei_json(json_lines: str):
    findings = []
    for line in json_lines.strip().split(chr(10)):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO,
        }
        sev = severity_map.get(data.get('info', {}).get('severity', '').lower(), Severity.UNKNOWN)
        matched = data.get('matched-at', '')
        host, port = _extract_host_port(matched)
        finding = Finding(
            tool='nuclei',
            vuln_type=data.get('info', {}).get('name', 'nuclei-finding'),
            title=data.get('info', {}).get('name', ''),
            description=data.get('info', {}).get('description', ''),
            host=host,
            port=port,
            parameter=data.get('template-id', ''),
            evidence={
                'matched_at': matched,
                'extracted_results': data.get('extracted-results', []),
                'curl_command': data.get('curl-command', ''),
                'template_id': data.get('template-id', ''),
                'template_path': data.get('template-path', ''),
            },
            cvss_vector='',
            cvss_score=0.0,
            severity=sev,
            cve_ids=_extract_cves(data.get('info', {})),
            references=data.get('info', {}).get('reference', []),
            tags=data.get('info', {}).get('tags', []),
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    return findings


def parse_ffuf_json(json_str: str):
    findings = []
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return findings
    results = data.get('results', [])
    for result in results:
        url = result.get('url', '')
        host, port = _extract_host_port(url)
        status = result.get('status', 0)
        length = result.get('length', 0)
        words = result.get('words', 0)
        lines = result.get('lines', 0)
        if 500 <= status < 600:
            sev = Severity.MEDIUM
        elif 400 <= status < 500:
            sev = Severity.LOW
        elif 200 <= status < 300:
            sev = Severity.INFO
        else:
            sev = Severity.INFO
        finding = Finding(
            tool='ffuf',
            vuln_type='directory_discovery',
            title='Discovered path: ' + url,
            description='HTTP ' + str(status) + ' - Length: ' + str(length) + ', Words: ' + str(words) + ', Lines: ' + str(lines),
            host=host,
            port=port,
            parameter=url,
            evidence={
                'url': url,
                'status': status,
                'length': length,
                'words': words,
                'lines': lines,
                'redirect_location': result.get('redirectlocation', ''),
                'content_type': result.get('content-type', ''),
            },
            cvss_vector='',
            cvss_score=0.0,
            severity=sev,
            tags=['web', 'directory', 'discovery'],
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    return findings


def parse_sqlmap_json(json_str: str):
    findings = []
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return findings
    if isinstance(data, dict):
        findings.extend(_parse_sqlmap_target(data))
    elif isinstance(data, list):
        for target in data:
            findings.extend(_parse_sqlmap_target(target))
    return findings


def _parse_sqlmap_target(target):
    findings = []
    url = target.get('url', '')
    host, port = _extract_host_port(url)
    for inj in target.get('injection_points', []):
        param = inj.get('parameter', '')
        ptype = inj.get('type', '')
        title = 'SQL Injection in parameter ' + param + ' (' + ptype + ')'
        finding = Finding(
            tool='sqlmap',
            vuln_type='sql_injection',
            title=title,
            description='SQL injection via ' + ptype + ' in parameter ' + param,
            host=host,
            port=port,
            parameter=param,
            evidence={
                'url': url,
                'injection_type': ptype,
                'parameter': param,
                'payloads': inj.get('payloads', []),
                'dbms': target.get('dbms', ''),
                'technique': inj.get('technique', ''),
            },
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            cve_ids=[],
            references=['https://owasp.org/Top10/A03_2021-Injection/'],
            tags=['injection', 'sql', 'database'],
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    for table in target.get('tables', []):
        finding = Finding(
            tool='sqlmap',
            vuln_type='data_exposure',
            title='Database table dumped: ' + table.get('name', ''),
            description='Successfully dumped table with ' + str(table.get('entries', 0)) + ' entries',
            host=host,
            port=port,
            parameter='',
            evidence={
                'table': table.get('name', ''),
                'columns': table.get('columns', []),
                'entries': table.get('entries', 0),
                'sample_data': table.get('data', [])[:5],
            },
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            cvss_score=7.5,
            severity=Severity.HIGH,
            tags=['data_exposure', 'sql', 'database'],
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    return findings


def parse_hydra_json(json_str: str):
    findings = []
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        for line in json_str.strip().split(chr(10)):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.extend(_parse_hydra_result(data))
            except json.JSONDecodeError:
                continue
        return findings
    if isinstance(data, list):
        for item in data:
            findings.extend(_parse_hydra_result(item))
    else:
        findings.extend(_parse_hydra_result(data))
    return findings


def _parse_hydra_result(data):
    findings = []
    host = data.get('host', '')
    port = data.get('port', 0)
    login = data.get('login', '')
    password = data.get('password', '')
    service = data.get('service', '')
    if login and password:
        finding = Finding(
            tool='hydra',
            vuln_type='credential_brute_force',
            title='Valid credentials found: ' + login + ':' + password,
            description='Brute force successful for ' + service + ' on ' + host + ':' + str(port),
            host=host,
            port=port,
            parameter=service + '://' + login,
            evidence={
                'service': service,
                'login': login,
                'password': password,
                'host': host,
                'port': port,
            },
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            tags=['brute_force', 'credentials', 'authentication'],
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    return findings


def parse_masscan_json(json_lines: str):
    hosts_dict = {}
    for line in json_lines.strip().split(chr(10)):
        line = line.strip()
        if not line or line.startswith('['):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = data.get('ip', '')
        if not ip:
            continue
        if ip not in hosts_dict:
            hosts_dict[ip] = Host(address=ip)
        for port_info in data.get('ports', []):
            port_num = port_info.get('port', 0)
            proto = port_info.get('proto', 'tcp')
            port = Port(number=port_num, protocol=proto, state='open', service=Service(name=''))
            hosts_dict[ip].ports.append(port)
    return list(hosts_dict.values())


def parse_amass_json(json_lines: str):
    findings = []
    for line in json_lines.strip().split(chr(10)):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = data.get('name', '')
        if not name:
            continue
        finding = Finding(
            tool='amass',
            vuln_type='subdomain_enumeration',
            title='Subdomain discovered: ' + name,
            description='Discovered via ' + data.get('source', 'unknown'),
            host=name,
            port=None,
            parameter='',
            evidence={
                'source': data.get('source', ''),
                'tag': data.get('tag', ''),
                'ip_addresses': data.get('ip_addresses', []),
                'asn': data.get('asn', ''),
                'cidr': data.get('cidr', ''),
            },
            cvss_vector='',
            cvss_score=0.0,
            severity=Severity.INFO,
            tags=['recon', 'subdomain', 'dns'],
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    return findings


def parse_generic(text: str, tool: str):
    findings = []
    patterns = {
        'url': r'https?://[^\s]+',
        'ip_port': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})',
        'cve': r'CVE-\d{4}-\d{4,}',
        'cvss': r'CVSS:3\.[01]/[A-Z:/\.]+',
    }
    for match in re.finditer(patterns['url'], text):
        url = match.group(0)
        host, port = _extract_host_port(url)
        finding = Finding(
            tool=tool,
            vuln_type='discovered_url',
            title='URL found: ' + url,
            description='Discovered in ' + tool + ' output',
            host=host,
            port=port,
            parameter=url,
            evidence={'source_text': text[max(0, match.start()-50):match.end()+50]},
            cvss_vector='',
            cvss_score=0.0,
            severity=Severity.INFO,
            tags=['discovery', 'url'],
        )
        finding.compute_dedup_hash()
        findings.append(finding)
    return findings


PARSERS = {
    'nmap_xml': parse_nmap_xml,
    'nuclei_json': parse_nuclei_json,
    'ffuf_json': parse_ffuf_json,
    'sqlmap_json': parse_sqlmap_json,
    'hydra_json': parse_hydra_json,
    'masscan_json': parse_masscan_json,
    'amass_json': parse_amass_json,
    'generic': parse_generic,
}

def parse_output(parser_name: str, output: str, tool: str = ''):
    parser = PARSERS.get(parser_name)
    if parser:
        return parser(output)
    return parse_generic(output, tool or parser_name)

def parse_scan_result(parser_name: str, output: str, tool: str, target: str, command: str):
    from .models import ScanResult
    findings = parse_output(parser_name, output, tool)
    hosts = []
    if parser_name in ('nmap_xml', 'masscan_json'):
        hosts = parse_output(parser_name, output, tool)
    return ScanResult(
        tool=tool,
        target=target,
        command=command,
        raw_output=output,
        parsed_hosts=hosts,
        parsed_findings=findings,
        duration=0.0,
    )

def _extract_host_port(url_or_target: str):
    if not url_or_target:
        return '', None
    if '://' in url_or_target:
        from urllib.parse import urlparse
        parsed = urlparse(url_or_target)
        host = parsed.hostname or ''
        port = parsed.port
        if port is None:
            if parsed.scheme == 'https':
                port = 443
            elif parsed.scheme == 'http':
                port = 80
        return host, port
    if ':' in url_or_target and not url_or_target.startswith('['):
        parts = url_or_target.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
            return host, port
        except ValueError:
            return parts[0], None
    return url_or_target, None

def _extract_cves(info):
    cves = []
    for key in ('cve-id', 'cve', 'cves'):
        val = info.get(key)
        if val:
            if isinstance(val, list):
                cves.extend(val)
            else:
                cves.append(str(val))
    for ref in info.get('reference', []):
        if 'cve-' in ref.lower():
            match = re.search(r'CVE-\d{4}-\d{4,}', ref, re.IGNORECASE)
            if match:
                cves.append(match.group(0).upper())
    return list(set(cves))
