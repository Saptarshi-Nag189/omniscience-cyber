from __future__ import annotations

"""
rag/parsers.py — Parsers for Kali Linux tool scan outputs.

Parses raw outputs from Nmap, Nuclei, Ffuf, SQLMap, Hydra, Masscan, Amass,
and generic command outputs into unified Finding and Host models.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .models import Finding, Host, Port, ScanResult, Service, Severity, normalize_severity

logger = logging.getLogger(__name__)


# ── Helper Utilities ─────────────────────────────────────────────────────────

def _extract_host_port(url_or_target: str) -> Tuple[str, Optional[int]]:
    """
    Extract host and optional port from a URL, host:port string, or bare IP/hostname.
    Safely handles empty/malformed inputs, IPv6, and default URL scheme ports.
    """
    if not url_or_target or not isinstance(url_or_target, str):
        return "", None

    target = url_or_target.strip()
    if not target:
        return "", None

    # Handle standard URL schemes
    if "://" in target:
        try:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port
            if port is None:
                if parsed.scheme == "https":
                    port = 443
                elif parsed.scheme == "http":
                    port = 80
                elif parsed.scheme == "ssh":
                    port = 22
                elif parsed.scheme == "ftp":
                    port = 21
            return host, port
        except Exception:
            pass

    # Handle IPv6 with port e.g. [::1]:8080 or [2001:db8::1]
    if target.startswith("["):
        bracket_end = target.find("]")
        if bracket_end != -1:
            host = target[1:bracket_end]
            rest = target[bracket_end + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, None
            return host, None

    # Handle host:port (IPv4 or hostname)
    if ":" in target:
        parts = target.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
            return host, port
        except ValueError:
            return parts[0], None

    return target, None


def _extract_cves(info: Any) -> List[str]:
    """
    Extract and normalize CVE IDs from nuclei/tool info metadata or references.
    Always returns uppercase CVE IDs (e.g. ['CVE-2021-44228']).
    """
    if not isinstance(info, dict):
        return []

    cves: List[str] = []

    # Check top-level keys
    for key in ("cve-id", "cve_id", "cve", "cves"):
        val = info.get(key)
        if val:
            if isinstance(val, list):
                for item in val:
                    if item and isinstance(item, str):
                        cves.append(item.strip().upper())
            elif isinstance(val, str) and val.strip():
                cves.append(val.strip().upper())

    # Check classification block if present
    classification = info.get("classification")
    if isinstance(classification, dict):
        for key in ("cve-id", "cve_id", "cve", "cves"):
            val = classification.get(key)
            if val:
                if isinstance(val, list):
                    for item in val:
                        if item and isinstance(item, str):
                            cves.append(item.strip().upper())
                elif isinstance(val, str) and val.strip():
                    cves.append(val.strip().upper())

    # Scan references for CVE patterns
    refs = info.get("reference") or info.get("references") or []
    if isinstance(refs, str):
        refs = [refs]
    elif not isinstance(refs, list):
        refs = []

    for ref in refs:
        if isinstance(ref, str) and "cve-" in ref.lower():
            for match in re.finditer(r"CVE-\d{4}-\d{4,}", ref, re.IGNORECASE):
                cves.append(match.group(0).upper())

    # Deduplicate while preserving order
    seen = set()
    result = []
    for c in cves:
        normalized = c.upper()
        if normalized.startswith("CVE-") and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


# ── Tool Parsers ─────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_str: str) -> List[Host]:
    """
    Parse Nmap XML output string into a list of Host objects.
    Robustly handles malformed XML, missing tags, multiple addresses,
    port scripts, CPEs, OS detection, distance, and uptime.
    """
    if not xml_str or not isinstance(xml_str, str) or not xml_str.strip():
        return []

    try:
        root = ET.fromstring(xml_str.strip())
    except Exception as e:
        logger.debug("Failed to parse Nmap XML: %s", e)
        return []

    hosts: List[Host] = []

    # Support if root is itself a <host> element or standard <nmaprun>
    host_elements = [root] if root.tag == "host" else root.findall("host")

    for host_elem in host_elements:
        # Extract IP address (prefer IPv4 / IPv6 over MAC)
        address = ""
        addresses = host_elem.findall("address")
        for addr_elem in addresses:
            addr_type = addr_elem.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6") and not address:
                address = addr_elem.get("addr", "")
                break
        if not address and addresses:
            address = addresses[0].get("addr", "")

        # Extract host status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "up") if status_elem is not None else "up"
        reason = status_elem.get("reason", "") if status_elem is not None else ""

        # Extract hostnames
        hostnames: List[str] = []
        for hn in host_elem.findall("hostnames/hostname"):
            name = hn.get("name", "").strip()
            if name and name not in hostnames:
                hostnames.append(name)

        # Extract ports
        ports: List[Port] = []
        for port_elem in host_elem.findall("ports/port"):
            port_id_raw = port_elem.get("portid", "0")
            try:
                port_id = int(port_id_raw)
            except (ValueError, TypeError):
                port_id = 0

            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            port_reason = state_elem.get("reason", "") if state_elem is not None else ""
            port_reason_ttl_raw = state_elem.get("reason_ttl", "0") if state_elem is not None else "0"
            try:
                port_reason_ttl = int(port_reason_ttl_raw)
            except (ValueError, TypeError):
                port_reason_ttl = 0

            # Extract Service
            service_elem = port_elem.find("service")
            service: Optional[Service] = None
            if service_elem is not None:
                conf_raw = service_elem.get("conf", "0")
                try:
                    conf = int(conf_raw)
                except (ValueError, TypeError):
                    conf = 0

                cpes = [
                    cpe.text.strip()
                    for cpe in service_elem.findall("cpe")
                    if cpe.text and cpe.text.strip()
                ]

                service = Service(
                    name=service_elem.get("name", ""),
                    product=service_elem.get("product", ""),
                    version=service_elem.get("version", ""),
                    extrainfo=service_elem.get("extrainfo", ""),
                    ostype=service_elem.get("ostype", ""),
                    method=service_elem.get("method", ""),
                    conf=conf,
                    cpe=cpes,
                )

            # Extract Port Scripts
            scripts: List[Dict[str, Any]] = []
            for script in port_elem.findall("script"):
                scripts.append({
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                })

            ports.append(
                Port(
                    number=port_id,
                    protocol=protocol,
                    state=state,
                    service=service,
                    scripts=scripts,
                    reason=port_reason,
                    reason_ttl=port_reason_ttl,
                )
            )

        # Extract OS matches
        os_matches: List[Dict[str, Any]] = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })
        os_primary = os_matches[0] if os_matches else None

        # Extract distance
        distance: Optional[int] = None
        dist_elem = host_elem.find("distance")
        if dist_elem is not None:
            try:
                distance = int(dist_elem.get("value", "0"))
            except (ValueError, TypeError):
                distance = None

        # Extract uptime
        uptime: Optional[str] = None
        uptime_elem = host_elem.find("uptime")
        if uptime_elem is not None:
            uptime = uptime_elem.get("lastboot", "") or uptime_elem.get("seconds", "")

        hosts.append(
            Host(
                address=address,
                hostnames=hostnames,
                ports=ports,
                os=os_primary,
                os_matches=os_matches,
                distance=distance,
                uptime=uptime,
                status=status,
                reason=reason,
            )
        )

    return hosts


def parse_nuclei_json(json_lines: str) -> List[Finding]:
    """
    Parse Nuclei JSON or JSONL output into a list of Finding objects.
    Extracts CVEs, CVSS scores/metrics, matched URLs, severities, and tags.
    """
    if not json_lines or not isinstance(json_lines, str) or not json_lines.strip():
        return []

    findings: List[Finding] = []

    # Attempt to parse as a JSON array or single object first
    content = json_lines.strip()
    records: List[Dict[str, Any]] = []
    if content.startswith("[") or content.startswith("{"):
        try:
            parsed_json = json.loads(content)
            if isinstance(parsed_json, list):
                records = [item for item in parsed_json if isinstance(item, dict)]
            elif isinstance(parsed_json, dict):
                records = [parsed_json]
        except json.JSONDecodeError:
            pass

    # Fallback to line-by-line JSON parsing
    if not records:
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s or line_s in ("[", "]", ","):
                continue
            if line_s.endswith(","):
                line_s = line_s[:-1].strip()
            try:
                data = json.loads(line_s)
                if isinstance(data, dict):
                    records.append(data)
            except json.JSONDecodeError:
                continue

    for data in records:
        info = data.get("info", {})
        if not isinstance(info, dict):
            info = {}

        # Severity
        sev_raw = info.get("severity", "unknown")
        sev = normalize_severity(sev_raw)

        # Matched endpoint / host / port
        matched = (
            data.get("matched-at", "")
            or data.get("matched_at", "")
            or data.get("host", "")
            or data.get("url", "")
            or ""
        )
        host, port = _extract_host_port(matched)

        # Template ID & Titles
        template_id = (
            data.get("template-id", "")
            or data.get("template_id", "")
            or data.get("templateID", "")
            or ""
        )
        name = info.get("name", "") or template_id or "nuclei-finding"
        desc = info.get("description", "") or name
        vuln_type = template_id or name

        # Classification / CVSS
        classification = info.get("classification")
        if not isinstance(classification, dict):
            classification = {}

        cvss_vector = (
            classification.get("cvss-metrics", "")
            or info.get("cvss-metrics", "")
            or ""
        )
        cvss_score_raw = (
            classification.get("cvss-score", 0.0)
            or info.get("cvss-score", 0.0)
        )
        try:
            cvss_score = float(cvss_score_raw)
        except (ValueError, TypeError):
            cvss_score = 0.0

        # References
        refs = info.get("reference") or info.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        elif not isinstance(refs, list):
            refs = []

        # Tags
        tags_raw = info.get("tags") or []
        if isinstance(tags_raw, str):
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        elif isinstance(tags_raw, list):
            tags = [str(t) for t in tags_raw]
        else:
            tags = []
        if "nuclei" not in tags:
            tags.append("nuclei")

        # Evidence
        evidence = {
            "matched_at": matched,
            "template_id": template_id,
            "template_path": data.get("template-path", "") or data.get("template", ""),
            "extracted_results": data.get("extracted-results", []) or data.get("extracted_results", []),
            "curl_command": data.get("curl-command", "") or data.get("curl_command", ""),
            "type": data.get("type", ""),
            "matcher_name": data.get("matcher-name", "") or data.get("matcher_name", ""),
        }

        finding = Finding(
            tool="nuclei",
            vuln_type=vuln_type,
            title=name,
            description=desc,
            host=host,
            port=port,
            target=matched or host,
            parameter=template_id,
            evidence=evidence,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            severity=sev,
            cve_ids=_extract_cves(info),
            references=refs,
            tags=tags,
            raw_output=json.dumps(data) if isinstance(data, dict) else "",
        )
        finding.compute_dedup_hash()
        findings.append(finding)

    return findings


def parse_ffuf_json(json_str: str) -> List[Finding]:
    """
    Parse ffuf JSON output into a list of Finding objects.
    Captures status codes, word/line/byte counts, endpoints, and fuzz parameters.
    """
    if not json_str or not isinstance(json_str, str) or not json_str.strip():
        return []

    findings: List[Finding] = []
    content = json_str.strip()

    raw_results: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if "results" in data and isinstance(data["results"], list):
                raw_results = data["results"]
            else:
                raw_results = [data]
        elif isinstance(data, list):
            raw_results = data
    except json.JSONDecodeError:
        # Fallback to line-by-line JSON
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s or line_s in ("[", "]", ","):
                continue
            if line_s.endswith(","):
                line_s = line_s[:-1].strip()
            try:
                line_obj = json.loads(line_s)
                if isinstance(line_obj, dict):
                    if "results" in line_obj and isinstance(line_obj["results"], list):
                        raw_results.extend(line_obj["results"])
                    else:
                        raw_results.append(line_obj)
            except json.JSONDecodeError:
                continue

    for result in raw_results:
        if not isinstance(result, dict):
            continue

        url = result.get("url", "")
        host, port = _extract_host_port(url)

        try:
            status = int(result.get("status", 0))
        except (ValueError, TypeError):
            status = 0

        try:
            length = int(result.get("length", 0))
        except (ValueError, TypeError):
            length = 0

        try:
            words = int(result.get("words", 0))
        except (ValueError, TypeError):
            words = 0

        try:
            lines = int(result.get("lines", 0))
        except (ValueError, TypeError):
            lines = 0

        input_data = result.get("input", {})
        param_val = ""
        if isinstance(input_data, dict):
            param_val = input_data.get("FUZZ", "") or (next(iter(input_data.values()), "") if input_data else "")
        elif isinstance(input_data, str):
            param_val = input_data

        # Severity mapping
        if 500 <= status < 600:
            sev = Severity.MEDIUM
        elif status in (401, 403):
            sev = Severity.LOW
        elif 200 <= status < 400:
            sev = Severity.INFO
        else:
            sev = Severity.INFO

        evidence = {
            "url": url,
            "status": status,
            "length": length,
            "words": words,
            "lines": lines,
            "redirect_location": result.get("redirectlocation", ""),
            "content_type": result.get("content-type", ""),
            "input": input_data,
        }

        finding = Finding(
            tool="ffuf",
            vuln_type="directory_discovery",
            title=f"Discovered path: {url}",
            description=f"HTTP {status} - Length: {length}, Words: {words}, Lines: {lines}",
            host=host,
            port=port,
            target=url or host,
            parameter=str(param_val) if param_val else url,
            evidence=evidence,
            cvss_vector="",
            cvss_score=0.0,
            severity=sev,
            tags=["web", "directory", "discovery", "ffuf"],
        )
        finding.compute_dedup_hash()
        findings.append(finding)

    return findings


def parse_sqlmap_json(json_str: str) -> List[Finding]:
    """
    Parse SQLMap JSON output into a list of Finding objects.
    Captures SQL injection vulnerabilities and dumped database tables.
    """
    if not json_str or not isinstance(json_str, str) or not json_str.strip():
        return []

    findings: List[Finding] = []
    content = json_str.strip()

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Fallback to line-by-line parsing
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s:
                continue
            try:
                line_data = json.loads(line_s)
                if isinstance(line_data, dict):
                    findings.extend(_parse_sqlmap_target(line_data))
                elif isinstance(line_data, list):
                    for target in line_data:
                        if isinstance(target, dict):
                            findings.extend(_parse_sqlmap_target(target))
            except json.JSONDecodeError:
                continue
        return findings

    if isinstance(data, dict):
        findings.extend(_parse_sqlmap_target(data))
    elif isinstance(data, list):
        for target in data:
            if isinstance(target, dict):
                findings.extend(_parse_sqlmap_target(target))

    return findings


def _parse_sqlmap_target(target: Dict[str, Any]) -> List[Finding]:
    """Helper to parse a single SQLMap target object."""
    findings: List[Finding] = []
    if not isinstance(target, dict):
        return findings

    url = target.get("url", "") or target.get("target", "")
    host, port = _extract_host_port(url)
    dbms = target.get("dbms", "")

    # Parse injection points
    injection_points = (
        target.get("injection_points", [])
        or target.get("data", [])
        or target.get("injections", [])
    )
    if isinstance(injection_points, list):
        for inj in injection_points:
            if not isinstance(inj, dict):
                continue
            param = inj.get("parameter", "") or inj.get("param", "") or inj.get("place", "")
            ptype = inj.get("type", "") or inj.get("technique", "") or inj.get("title", "SQL Injection")
            title = f"SQL Injection in parameter {param} ({ptype})" if param else f"SQL Injection ({ptype})"

            evidence = {
                "url": url,
                "injection_type": ptype,
                "parameter": param,
                "payloads": inj.get("payloads", []) or ([inj.get("payload", "")] if inj.get("payload") else []),
                "dbms": dbms,
                "technique": inj.get("technique", ""),
                "place": inj.get("place", ""),
            }

            finding = Finding(
                tool="sqlmap",
                vuln_type="sql_injection",
                title=title,
                description=f"SQL injection via {ptype} in parameter {param}" if param else f"SQL injection via {ptype}",
                host=host,
                port=port,
                target=url or host,
                parameter=param,
                evidence=evidence,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
                severity=Severity.CRITICAL,
                cve_ids=[],
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                tags=["injection", "sql", "database", "sqlmap"],
            )
            finding.compute_dedup_hash()
            findings.append(finding)

    # Parse dumped tables
    dump_dict = target.get("dump")
    dump_tables = dump_dict.get("tables", []) if isinstance(dump_dict, dict) else []
    tables = target.get("tables", []) or dump_tables
    if isinstance(tables, list):
        for table in tables:
            if not isinstance(table, dict):
                continue
            tbl_name = table.get("name", "") or table.get("table", "")
            entries_raw = table.get("entries", 0) or table.get("count", 0)
            try:
                entries = int(entries_raw)
            except (ValueError, TypeError):
                entries = 0

            columns = table.get("columns", [])
            data_sample = table.get("data", [])
            if isinstance(data_sample, list):
                data_sample = data_sample[:5]
            else:
                data_sample = []

            evidence = {
                "table": tbl_name,
                "columns": columns,
                "entries": entries,
                "sample_data": data_sample,
                "dbms": dbms,
            }

            finding = Finding(
                tool="sqlmap",
                vuln_type="data_exposure",
                title=f"Database table dumped: {tbl_name}" if tbl_name else "Database table dumped",
                description=f"Successfully dumped table {tbl_name} with {entries} entries" if tbl_name else f"Successfully dumped table with {entries} entries",
                host=host,
                port=port,
                target=url or host,
                parameter=tbl_name,
                evidence=evidence,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                severity=Severity.HIGH,
                tags=["data_exposure", "sql", "database", "sqlmap"],
            )
            finding.compute_dedup_hash()
            findings.append(finding)

    return findings


def parse_hydra_json(json_str: str) -> List[Finding]:
    """
    Parse Hydra JSON output (or fallback text output) into a list of Finding objects.
    Captures credentials, targeted hosts, ports, and services.
    """
    if not json_str or not isinstance(json_str, str) or not json_str.strip():
        return []

    findings: List[Finding] = []
    content = json_str.strip()

    # Try full JSON parse
    parsed_items: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            parsed_items = [i for i in data if isinstance(i, dict)]
        elif isinstance(data, dict):
            if "results" in data and isinstance(data["results"], list):
                parsed_items = [i for i in data["results"] if isinstance(i, dict)]
            else:
                parsed_items = [data]
    except json.JSONDecodeError:
        # Try line-by-line JSON
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s:
                continue
            try:
                line_data = json.loads(line_s)
                if isinstance(line_data, dict):
                    if "results" in line_data and isinstance(line_data["results"], list):
                        parsed_items.extend([i for i in line_data["results"] if isinstance(i, dict)])
                    else:
                        parsed_items.append(line_data)
                elif isinstance(line_data, list):
                    parsed_items.extend([i for i in line_data if isinstance(i, dict)])
            except json.JSONDecodeError:
                continue

    for item in parsed_items:
        findings.extend(_parse_hydra_result(item))

    # If no findings found from JSON, fallback to standard Hydra plain text regex
    if not findings:
        hydra_pattern_primary = re.compile(
            r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)",
            re.IGNORECASE,
        )
        hydra_pattern_fallback = re.compile(
            r"host:\s*(?P<host>\S+)\s+(?:port:\s*(?P<port>\d+)\s+)?login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)",
            re.IGNORECASE,
        )
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            m = hydra_pattern_primary.search(line_str) or hydra_pattern_fallback.search(line_str)
            if m:
                d = m.groupdict()
                port_val = d.get("port")
                item = {
                    "host": d.get("host", ""),
                    "port": int(port_val) if port_val and port_val.isdigit() else None,
                    "service": d.get("service", ""),
                    "login": d.get("login", ""),
                    "password": d.get("password", ""),
                }
                findings.extend(_parse_hydra_result(item))

    return findings


def _parse_hydra_result(data: Dict[str, Any]) -> List[Finding]:
    """Helper to convert a Hydra result dict into a Finding object."""
    findings: List[Finding] = []
    if not isinstance(data, dict):
        return findings

    host = str(data.get("host", "") or data.get("target", "")).strip()
    port_raw = data.get("port")
    try:
        port = int(port_raw) if port_raw is not None and str(port_raw).isdigit() else None
    except (ValueError, TypeError):
        port = None

    login = str(data.get("login", "") or data.get("user", "") or data.get("username", "")).strip()
    password = str(data.get("password", "") or data.get("pass", "")).strip()
    service = str(data.get("service", "") or data.get("protocol", "") or data.get("proto", "")).strip()

    if login and password:
        target_str = f"{host}:{port}" if port else host
        param_str = f"{service}://{login}" if service else login
        svc_str = service or "service"

        evidence = {
            "service": service,
            "login": login,
            "password": password,
            "host": host,
            "port": port,
        }

        finding = Finding(
            tool="hydra",
            vuln_type="credential_brute_force",
            title=f"Valid credentials found: {login}:{password}",
            description=f"Brute force successful for {svc_str} on {target_str}",
            host=host,
            port=port,
            target=target_str,
            parameter=param_str,
            evidence=evidence,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            tags=["brute_force", "credentials", "authentication", "hydra"],
        )
        finding.compute_dedup_hash()
        findings.append(finding)

    return findings


def parse_masscan_json(json_lines: str) -> List[Host]:
    """
    Parse Masscan JSON or JSON-lines output into a list of Host objects.
    Groups discovered ports by host IP address.
    """
    if not json_lines or not isinstance(json_lines, str) or not json_lines.strip():
        return []

    hosts_dict: Dict[str, Host] = {}
    content = json_lines.strip()

    records: List[Dict[str, Any]] = []

    # Attempt to parse whole JSON array
    try:
        data = json.loads(content)
        if isinstance(data, list):
            records = [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            records = [data]
    except json.JSONDecodeError:
        # Fallback to line-by-line parsing
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s or line_s in ("[", "]", ","):
                continue
            if line_s.startswith(","):
                line_s = line_s[1:].strip()
            if line_s.endswith(","):
                line_s = line_s[:-1].strip()
            try:
                item = json.loads(line_s)
                if isinstance(item, dict):
                    records.append(item)
            except json.JSONDecodeError:
                continue

    for data in records:
        ip = data.get("ip", "").strip()
        if not ip:
            continue

        if ip not in hosts_dict:
            hosts_dict[ip] = Host(address=ip, status="up")

        for port_info in data.get("ports", []):
            if not isinstance(port_info, dict):
                continue
            port_num_raw = port_info.get("port", 0)
            try:
                port_num = int(port_num_raw)
            except (ValueError, TypeError):
                port_num = 0

            proto = port_info.get("proto", "tcp")
            status = port_info.get("status", "open")
            reason = port_info.get("reason", "syn-ack")
            ttl_raw = port_info.get("ttl", 0)
            try:
                ttl = int(ttl_raw)
            except (ValueError, TypeError):
                ttl = 0

            port = Port(
                number=port_num,
                protocol=proto,
                state=status,
                reason=reason,
                reason_ttl=ttl,
                service=Service(name=""),
            )
            hosts_dict[ip].ports.append(port)

    return list(hosts_dict.values())


def parse_amass_json(json_lines: str) -> List[Finding]:
    """
    Parse OWASP Amass JSON or JSONL output into a list of Finding objects.
    Extracts subdomains, sources, IP addresses, ASNs, and CIDRs.
    """
    if not json_lines or not isinstance(json_lines, str) or not json_lines.strip():
        return []

    findings: List[Finding] = []
    content = json_lines.strip()

    records: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            records = [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            records = [data]
    except json.JSONDecodeError:
        pass

    if not records:
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s or line_s in ("[", "]", ","):
                continue
            if line_s.endswith(","):
                line_s = line_s[:-1].strip()
            try:
                data = json.loads(line_s)
                if isinstance(data, dict):
                    records.append(data)
            except json.JSONDecodeError:
                continue

    for data in records:
        name = data.get("name", "").strip()
        if not name:
            continue

        domain = data.get("domain", "").strip()

        # Handle source / sources
        sources_raw = data.get("sources") or data.get("source") or []
        if isinstance(sources_raw, list):
            sources_list = [str(s) for s in sources_raw]
            sources_str = ", ".join(sources_list)
        elif isinstance(sources_raw, str) and sources_raw.strip():
            sources_list = [sources_raw.strip()]
            sources_str = sources_raw.strip()
        else:
            sources_list = []
            sources_str = "unknown"

        tag = data.get("tag", "")

        # Extract IP addresses
        ip_addresses: List[str] = []
        asn = str(data.get("asn", "") or "").strip()
        cidr = str(data.get("cidr", "") or "").strip()
        addrs = data.get("addresses") or data.get("ip_addresses") or []
        if isinstance(addrs, list):
            for addr in addrs:
                if isinstance(addr, dict):
                    if "ip" in addr:
                        ip_addresses.append(str(addr["ip"]))
                    if not asn and "asn" in addr and addr["asn"] is not None:
                        asn = str(addr["asn"]).strip()
                    if not cidr and "cidr" in addr and addr["cidr"]:
                        cidr = str(addr["cidr"]).strip()
                elif isinstance(addr, str) and addr.strip():
                    ip_addresses.append(addr.strip())

        evidence = {
            "name": name,
            "domain": domain,
            "source": sources_str,
            "sources": sources_list,
            "tag": tag,
            "ip_addresses": ip_addresses,
            "asn": asn,
            "cidr": cidr,
        }

        finding = Finding(
            tool="amass",
            vuln_type="subdomain_enumeration",
            title=f"Subdomain discovered: {name}",
            description=f"Discovered subdomain {name} via {sources_str}",
            host=name,
            port=None,
            target=name,
            parameter=domain or name,
            evidence=evidence,
            cvss_vector="",
            cvss_score=0.0,
            severity=Severity.INFO,
            tags=["recon", "subdomain", "dns", "amass"],
        )
        finding.compute_dedup_hash()
        findings.append(finding)

    return findings


def parse_generic(text: str, tool: str = "generic") -> List[Finding]:
    """
    Generic regex-based parser extracting URLs, IP:port combinations, CVE IDs,
    and CVSS vectors from arbitrary tool output strings.
    """
    if not text or not isinstance(text, str) or not text.strip():
        return []

    findings: List[Finding] = []
    seen_hashes = set()

    # Regex patterns
    url_pattern = r"https?://[^\s\"\'<>]+"
    ip_port_pattern = r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b"
    cve_pattern = r"\bCVE-\d{4}-\d{4,}\b"

    # 1. URLs
    for match in re.finditer(url_pattern, text):
        url = match.group(0).rstrip(".,;)")
        host, port = _extract_host_port(url)
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 50)
        snippet = text[start:end].strip()

        finding = Finding(
            tool=tool,
            vuln_type="discovered_url",
            title=f"URL found: {url}",
            description=f"Discovered in {tool} output",
            host=host,
            port=port,
            target=url or host,
            parameter=url,
            evidence={"url": url, "snippet": snippet},
            cvss_vector="",
            cvss_score=0.0,
            severity=Severity.INFO,
            tags=["discovery", "url", tool],
        )
        finding.compute_dedup_hash()
        if finding.dedup_hash not in seen_hashes:
            seen_hashes.add(finding.dedup_hash)
            findings.append(finding)

    # 2. IP:Port pairs
    for match in re.finditer(ip_port_pattern, text):
        ip_str = match.group(1)
        port_str = match.group(2)
        try:
            port_num = int(port_str)
            if not (1 <= port_num <= 65535):
                continue
        except (ValueError, TypeError):
            continue

        target_str = f"{ip_str}:{port_num}"
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 50)
        snippet = text[start:end].strip()

        finding = Finding(
            tool=tool,
            vuln_type="discovered_service",
            title=f"Discovered service on {target_str}",
            description=f"Discovered service {target_str} in {tool} output",
            host=ip_str,
            port=port_num,
            target=target_str,
            parameter="",
            evidence={"ip": ip_str, "port": port_num, "snippet": snippet},
            cvss_vector="",
            cvss_score=0.0,
            severity=Severity.INFO,
            tags=["discovery", "network", tool],
        )
        finding.compute_dedup_hash()
        if finding.dedup_hash not in seen_hashes:
            seen_hashes.add(finding.dedup_hash)
            findings.append(finding)

    # 3. CVEs
    for match in re.finditer(cve_pattern, text, re.IGNORECASE):
        cve_id = match.group(0).upper()
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 50)
        snippet = text[start:end].strip()

        finding = Finding(
            tool=tool,
            vuln_type="discovered_vulnerability",
            title=f"Vulnerability mentioned: {cve_id}",
            description=f"CVE {cve_id} detected in {tool} output",
            host="",
            port=None,
            target="",
            parameter="",
            evidence={"cve": cve_id, "snippet": snippet},
            cvss_vector="",
            cvss_score=0.0,
            severity=Severity.MEDIUM,
            cve_ids=[cve_id],
            tags=["vulnerability", "cve", tool],
        )
        finding.compute_dedup_hash()
        if finding.dedup_hash not in seen_hashes:
            seen_hashes.add(finding.dedup_hash)
            findings.append(finding)

    return findings


# ── Registry & Dispatch ───────────────────────────────────────────────────────

PARSERS = {
    "nmap": parse_nmap_xml,
    "nmap_xml": parse_nmap_xml,
    "nuclei": parse_nuclei_json,
    "nuclei_json": parse_nuclei_json,
    "ffuf": parse_ffuf_json,
    "ffuf_json": parse_ffuf_json,
    "sqlmap": parse_sqlmap_json,
    "sqlmap_json": parse_sqlmap_json,
    "hydra": parse_hydra_json,
    "hydra_json": parse_hydra_json,
    "masscan": parse_masscan_json,
    "masscan_json": parse_masscan_json,
    "amass": parse_amass_json,
    "amass_json": parse_amass_json,
    "generic": parse_generic,
}


def parse_output(
    parser_name: str,
    output: str,
    tool: str = "",
) -> Union[List[Finding], List[Host]]:
    """
    Dispatch scan output to the named parser function.
    Gracefully falls back to parse_generic if specialized parser is not found
    or on unexpected errors.
    """
    if not output or not isinstance(output, str):
        return []

    norm_name = (parser_name or "").lower().strip()
    parser_fn = PARSERS.get(norm_name)

    try:
        if parser_fn:
            if parser_fn is parse_generic:
                return parser_fn(output, tool=tool or norm_name)
            return parser_fn(output)
        return parse_generic(output, tool=tool or parser_name or "generic")
    except Exception as e:
        logger.warning("Parser '%s' encountered an unexpected error: %s", parser_name, e)
        try:
            return parse_generic(output, tool=tool or parser_name or "generic")
        except Exception:
            return []


def parse_scan_result(
    parser_name: str,
    output: str,
    tool: str = "",
    target: str = "",
    command: str = "",
) -> ScanResult:
    """
    Parse scan output into a complete ScanResult object.
    Properly segments parsed hosts and findings based on parser output type.
    """
    parsed = parse_output(parser_name, output, tool=tool)

    hosts: List[Host] = []
    findings: List[Finding] = []

    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, Host):
                hosts.append(item)
            elif isinstance(item, Finding):
                findings.append(item)

    return ScanResult(
        tool=tool or parser_name or "generic",
        target=target,
        command=command,
        raw_output=output or "",
        parsed_hosts=hosts,
        hosts=hosts,
        parsed_findings=findings,
        findings=findings,
        duration=0.0,
    )
