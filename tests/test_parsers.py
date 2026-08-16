import json
import pytest

from rag.models import Finding, Host, Port, ScanResult, Service, Severity
from rag.parsers import (
    PARSERS,
    _extract_cves,
    _extract_host_port,
    parse_amass_json,
    parse_ffuf_json,
    parse_generic,
    parse_hydra_json,
    parse_masscan_json,
    parse_nmap_xml,
    parse_nuclei_json,
    parse_output,
    parse_scan_result,
    parse_sqlmap_json,
)


# ── Helper Utility Tests ──────────────────────────────────────────────────────

def test_extract_host_port():
    assert _extract_host_port("http://example.com") == ("example.com", 80)
    assert _extract_host_port("https://example.com") == ("example.com", 443)
    assert _extract_host_port("ssh://10.0.0.1") == ("10.0.0.1", 22)
    assert _extract_host_port("ftp://ftp.example.com") == ("ftp.example.com", 21)
    assert _extract_host_port("https://target.local:8443/api/v1") == ("target.local", 8443)
    assert _extract_host_port("192.168.1.1:8080") == ("192.168.1.1", 8080)
    assert _extract_host_port("target.local:9000") == ("target.local", 9000)
    assert _extract_host_port("192.168.1.1") == ("192.168.1.1", None)
    assert _extract_host_port("target.local") == ("target.local", None)
    assert _extract_host_port("[2001:db8::1]:8080") == ("2001:db8::1", 8080)
    assert _extract_host_port("[2001:db8::1]") == ("2001:db8::1", None)
    assert _extract_host_port("") == ("", None)
    assert _extract_host_port(None) == ("", None)


def test_extract_cves():
    info_dict = {
        "cve-id": ["CVE-2021-44228", "cve-2022-22965"],
        "classification": {"cve-id": "CVE-2023-1234"},
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://example.com/advisory?id=CVE-2020-0001",
        ],
    }
    cves = _extract_cves(info_dict)
    assert "CVE-2021-44228" in cves
    assert "CVE-2022-22965" in cves
    assert "CVE-2023-1234" in cves
    assert "CVE-2020-0001" in cves
    # Check deduplication
    assert len(cves) == len(set(cves))
    # Check non-dict input
    assert _extract_cves(None) == []
    assert _extract_cves("string") == []


# ── Nmap XML Tests ────────────────────────────────────────────────────────────

def test_parse_nmap_xml_valid():
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O 192.168.1.1" start="1610000000" version="7.91">
<host starttime="1610000000" endtime="1610000010">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames>
        <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack" reason_ttl="64"/>
            <service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" conf="10">
                <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
            </service>
            <script id="http-title" output="Test Router WebGUI"/>
        </port>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" reason_ttl="64"/>
            <service name="ssh" product="OpenSSH" version="8.2p1" conf="10">
                <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
            </service>
        </port>
        <port protocol="tcp" portid="23">
            <state state="closed" reason="reset" reason_ttl="64"/>
        </port>
    </ports>
    <os>
        <osmatch name="Linux 5.4" accuracy="98"/>
    </os>
    <distance value="1"/>
    <uptime seconds="360000" lastboot="2026-08-01 12:00:00"/>
</host>
</nmaprun>
"""
    hosts = parse_nmap_xml(xml_data)
    assert len(hosts) == 1
    host = hosts[0]
    assert host.address == "192.168.1.1"
    assert host.status == "up"
    assert host.hostnames == ["router.local"]
    assert host.distance == 1
    assert host.uptime == "2026-08-01 12:00:00"
    assert host.os == {"name": "Linux 5.4", "accuracy": "98"}

    assert len(host.ports) == 3
    open_ports = host.open_ports()
    assert len(open_ports) == 2
    assert [p.number for p in open_ports] == [80, 22]

    p80 = next(p for p in host.ports if p.number == 80)
    assert p80.protocol == "tcp"
    assert p80.state == "open"
    assert p80.service is not None
    assert p80.service.name == "http"
    assert p80.service.product == "Apache httpd"
    assert p80.service.version == "2.4.41"
    assert p80.service.cpe == ["cpe:/a:apache:http_server:2.4.41"]
    assert len(p80.scripts) == 1
    assert p80.scripts[0]["id"] == "http-title"
    assert p80.scripts[0]["output"] == "Test Router WebGUI"


def test_parse_nmap_xml_single_host_root():
    xml_data = """<host>
        <address addr="10.10.10.10" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https"/>
            </port>
        </ports>
    </host>"""
    hosts = parse_nmap_xml(xml_data)
    assert len(hosts) == 1
    assert hosts[0].address == "10.10.10.10"
    assert len(hosts[0].ports) == 1
    assert hosts[0].ports[0].number == 443


def test_parse_nmap_xml_empty_and_malformed():
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml(None) == []
    assert parse_nmap_xml("   ") == []
    assert parse_nmap_xml("<invalid xml <broken>") == []
    assert parse_nmap_xml("<nmaprun></nmaprun>") == []


# ── Nuclei JSON Tests ─────────────────────────────────────────────────────────

def test_parse_nuclei_json_valid():
    nuclei_lines = """
{"template-id":"cve-2021-44228","info":{"name":"Log4j Remote Code Execution","author":["pdteam"],"severity":"critical","description":"Apache Log4j2 JNDI RCE","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"classification":{"cve-id":["CVE-2021-44228"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0},"tags":["cve","cve2021","rce","log4j"]},"type":"http","host":"http://victim.local:8080","matched-at":"http://victim.local:8080/login","extracted-results":["jndi:ldap://attacker/a"],"curl-command":"curl -X POST 'http://victim.local:8080/login'"}
{"template-id":"apache-detect","info":{"name":"Apache HTTP Server Detection","severity":"info","tags":["tech","apache"]},"matched-at":"http://victim.local:8080"}
"""
    findings = parse_nuclei_json(nuclei_lines)
    assert len(findings) == 2

    f1 = findings[0]
    assert f1.tool == "nuclei"
    assert f1.vuln_type == "cve-2021-44228"
    assert f1.title == "Log4j Remote Code Execution"
    assert f1.severity == Severity.CRITICAL
    assert f1.host == "victim.local"
    assert f1.port == 8080
    assert f1.cve_ids == ["CVE-2021-44228"]
    assert f1.cvss_score == 10.0
    assert "CVSS:3.1" in f1.cvss_vector
    assert f1.evidence["matched_at"] == "http://victim.local:8080/login"
    assert f1.dedup_hash != ""

    f2 = findings[1]
    assert f2.severity == Severity.INFO
    assert f2.title == "Apache HTTP Server Detection"
    assert f2.dedup_hash != ""


def test_parse_nuclei_json_array():
    data = [
        {
            "template-id": "ssl-dns-names",
            "info": {"name": "SSL DNS Names", "severity": "info"},
            "matched-at": "https://example.com",
        }
    ]
    findings = parse_nuclei_json(json.dumps(data))
    assert len(findings) == 1
    assert findings[0].host == "example.com"
    assert findings[0].port == 443
    assert findings[0].severity == Severity.INFO


def test_parse_nuclei_json_empty_and_malformed():
    assert parse_nuclei_json("") == []
    assert parse_nuclei_json(None) == []
    assert parse_nuclei_json("   ") == []
    assert parse_nuclei_json("not a json string\nstill not json") == []


# ── FFUF JSON Tests ──────────────────────────────────────────────────────────

def test_parse_ffuf_json_valid():
    ffuf_data = {
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "position": 1,
                "status": 200,
                "length": 4532,
                "words": 312,
                "lines": 89,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://192.168.1.50/admin",
            },
            {
                "input": {"FUZZ": "secret"},
                "position": 2,
                "status": 403,
                "length": 162,
                "words": 15,
                "lines": 4,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://192.168.1.50/secret",
            },
            {
                "input": {"FUZZ": "crash"},
                "position": 3,
                "status": 500,
                "length": 890,
                "words": 45,
                "lines": 12,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://192.168.1.50/crash",
            },
        ]
    }
    findings = parse_ffuf_json(json.dumps(ffuf_data))
    assert len(findings) == 3

    assert findings[0].vuln_type == "directory_discovery"
    assert findings[0].host == "192.168.1.50"
    assert findings[0].port == 80
    assert findings[0].severity == Severity.INFO
    assert findings[0].parameter == "admin"
    assert findings[0].evidence["status"] == 200
    assert findings[0].dedup_hash != ""

    assert findings[1].severity == Severity.LOW
    assert findings[1].evidence["status"] == 403

    assert findings[2].severity == Severity.MEDIUM
    assert findings[2].evidence["status"] == 500


def test_parse_ffuf_json_empty_and_malformed():
    assert parse_ffuf_json("") == []
    assert parse_ffuf_json(None) == []
    assert parse_ffuf_json("{invalid json}") == []


# ── SQLMap JSON Tests ─────────────────────────────────────────────────────────

def test_parse_sqlmap_json_valid():
    sqlmap_data = {
        "url": "http://192.168.1.100/index.php?id=1",
        "dbms": "MySQL 5.7",
        "injection_points": [
            {
                "parameter": "id",
                "place": "GET",
                "type": "boolean-based blind",
                "technique": "AND boolean-based blind - WHERE or HAVING clause",
                "payloads": ["id=1 AND 1=1", "id=1 AND 1=2"],
            }
        ],
        "tables": [
            {
                "name": "users",
                "entries": 42,
                "columns": ["id", "username", "password"],
                "data": [
                    {"id": 1, "username": "admin", "password": "hashpassword"},
                    {"id": 2, "username": "user", "password": "userpassword"},
                ],
            }
        ],
    }
    findings = parse_sqlmap_json(json.dumps(sqlmap_data))
    assert len(findings) == 2

    inj_finding = findings[0]
    assert inj_finding.tool == "sqlmap"
    assert inj_finding.vuln_type == "sql_injection"
    assert inj_finding.severity == Severity.CRITICAL
    assert inj_finding.cvss_score == 9.8
    assert inj_finding.parameter == "id"
    assert inj_finding.host == "192.168.1.100"
    assert inj_finding.evidence["dbms"] == "MySQL 5.7"
    assert inj_finding.dedup_hash != ""

    table_finding = findings[1]
    assert table_finding.tool == "sqlmap"
    assert table_finding.vuln_type == "data_exposure"
    assert table_finding.severity == Severity.HIGH
    assert table_finding.cvss_score == 7.5
    assert table_finding.evidence["table"] == "users"
    assert table_finding.evidence["entries"] == 42
    assert table_finding.dedup_hash != ""


def test_parse_sqlmap_json_empty_and_malformed():
    assert parse_sqlmap_json("") == []
    assert parse_sqlmap_json(None) == []
    assert parse_sqlmap_json("corrupt data") == []


# ── Hydra JSON Tests ──────────────────────────────────────────────────────────

def test_parse_hydra_json_valid():
    hydra_data = [
        {
            "host": "192.168.1.20",
            "port": 22,
            "service": "ssh",
            "login": "root",
            "password": "toorpassword",
        }
    ]
    findings = parse_hydra_json(json.dumps(hydra_data))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "hydra"
    assert f.vuln_type == "credential_brute_force"
    assert f.severity == Severity.CRITICAL
    assert f.cvss_score == 9.8
    assert f.host == "192.168.1.20"
    assert f.port == 22
    assert f.evidence["login"] == "root"
    assert f.evidence["password"] == "toorpassword"
    assert f.dedup_hash != ""


def test_parse_hydra_plaintext_fallback():
    output = """
Hydra v9.2 (c) 2021 by van Hauser / THC & David Maciejak
[22][ssh] host: 192.168.1.20   login: admin   password: adminpassword
1 of 1 target completed, 1 valid password found
"""
    findings = parse_hydra_json(output)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "hydra"
    assert f.host == "192.168.1.20"
    assert f.port == 22
    assert f.evidence["login"] == "admin"
    assert f.evidence["password"] == "adminpassword"
    assert f.dedup_hash != ""


def test_parse_hydra_json_empty_and_malformed():
    assert parse_hydra_json("") == []
    assert parse_hydra_json(None) == []
    assert parse_hydra_json("no credentials found here") == []


# ── Masscan JSON Tests ────────────────────────────────────────────────────────

def test_parse_masscan_json_valid():
    masscan_output = """[
{ "ip": "10.0.0.1", "timestamp": "1610000000", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
,
{ "ip": "10.0.0.1", "timestamp": "1610000001", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
,
{ "ip": "10.0.0.2", "timestamp": "1610000002", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 56} ] }
]
"""
    hosts = parse_masscan_json(masscan_output)
    assert len(hosts) == 2

    h1 = next(h for h in hosts if h.address == "10.0.0.1")
    assert len(h1.ports) == 2
    assert [p.number for p in h1.ports] == [80, 443]
    assert h1.status == "up"

    h2 = next(h for h in hosts if h.address == "10.0.0.2")
    assert len(h2.ports) == 1
    assert h2.ports[0].number == 22


def test_parse_masscan_json_empty_and_malformed():
    assert parse_masscan_json("") == []
    assert parse_masscan_json(None) == []
    assert parse_masscan_json("[\n]") == []
    assert parse_masscan_json("corrupt data") == []


# ── Amass JSON Tests ──────────────────────────────────────────────────────────

def test_parse_amass_json_valid():
    amass_lines = """
{"name":"sub1.example.com","domain":"example.com","addresses":[{"ip":"192.168.1.10","cidr":"192.168.1.0/24","asn":12345}],"tag":"dns","sources":["DNS","Certspotter"]}
{"name":"sub2.example.com","domain":"example.com","addresses":[{"ip":"192.168.1.11"}],"tag":"cert","sources":["crtsh"]}
"""
    findings = parse_amass_json(amass_lines)
    assert len(findings) == 2

    f1 = findings[0]
    assert f1.tool == "amass"
    assert f1.vuln_type == "subdomain_enumeration"
    assert f1.host == "sub1.example.com"
    assert f1.severity == Severity.INFO
    assert f1.evidence["ip_addresses"] == ["192.168.1.10"]
    assert f1.evidence["asn"] == "12345"
    assert "DNS" in f1.evidence["source"]
    assert f1.dedup_hash != ""

    f2 = findings[1]
    assert f2.host == "sub2.example.com"
    assert f2.evidence["ip_addresses"] == ["192.168.1.11"]
    assert f2.dedup_hash != ""


def test_parse_amass_json_empty_and_malformed():
    assert parse_amass_json("") == []
    assert parse_amass_json(None) == []
    assert parse_amass_json("not amass json") == []


# ── Generic Parser Tests ──────────────────────────────────────────────────────

def test_parse_generic_discoveries():
    text = """
    Target web console found at https://app.example.com:8443/console.
    Internal service listening at 10.10.10.50:9000.
    Vulnerability identified: CVE-2023-38606 affects this version.
    """
    findings = parse_generic(text, "custom_tool")
    assert len(findings) == 3

    # URL finding
    url_f = next(f for f in findings if f.vuln_type == "discovered_url")
    assert url_f.tool == "custom_tool"
    assert url_f.host == "app.example.com"
    assert url_f.port == 8443
    assert url_f.severity == Severity.INFO
    assert url_f.dedup_hash != ""

    # Service finding
    svc_f = next(f for f in findings if f.vuln_type == "discovered_service")
    assert svc_f.host == "10.10.10.50"
    assert svc_f.port == 9000
    assert svc_f.severity == Severity.INFO
    assert svc_f.dedup_hash != ""

    # CVE finding
    cve_f = next(f for f in findings if f.vuln_type == "discovered_vulnerability")
    assert cve_f.cve_ids == ["CVE-2023-38606"]
    assert cve_f.severity == Severity.MEDIUM
    assert cve_f.dedup_hash != ""


def test_parse_generic_empty():
    assert parse_generic("") == []
    assert parse_generic(None) == []
    assert parse_generic("Nothing interesting here without patterns") == []


# ── Dispatcher and ScanResult Tests ───────────────────────────────────────────

def test_parse_output_dispatcher():
    # Nmap dispatch
    xml = """<nmaprun><host><address addr="10.0.0.1"/></host></nmaprun>"""
    nmap_res = parse_output("nmap_xml", xml)
    assert isinstance(nmap_res, list)
    assert len(nmap_res) == 1
    assert isinstance(nmap_res[0], Host)

    # Nuclei dispatch
    nuclei_line = '{"template-id":"t1","info":{"name":"T1","severity":"low"},"matched-at":"http://test.com"}'
    nuclei_res = parse_output("nuclei_json", nuclei_line)
    assert isinstance(nuclei_res, list)
    assert len(nuclei_res) == 1
    assert isinstance(nuclei_res[0], Finding)

    # Fallback to generic
    gen_res = parse_output("unknown_parser", "Discovered https://fallback.local:8080")
    assert isinstance(gen_res, list)
    assert len(gen_res) == 1
    assert isinstance(gen_res[0], Finding)


def test_parse_scan_result():
    xml = """<nmaprun><host><address addr="10.0.0.1"/><ports><port portid="80"><state state="open"/></port></ports></host></nmaprun>"""
    res = parse_scan_result(
        parser_name="nmap_xml",
        output=xml,
        tool="nmap",
        target="10.0.0.1",
        command="nmap -sS 10.0.0.1",
    )
    assert isinstance(res, ScanResult)
    assert res.tool == "nmap"
    assert res.target == "10.0.0.1"
    assert res.command == "nmap -sS 10.0.0.1"
    assert len(res.parsed_hosts) == 1
    assert len(res.hosts) == 1
    assert res.hosts[0].address == "10.0.0.1"
    assert len(res.hosts[0].ports) == 1
    assert len(res.parsed_findings) == 0

    nuclei_line = '{"template-id":"vuln1","info":{"name":"Vuln1","severity":"high"},"matched-at":"http://10.0.0.1"}'
    res_nuclei = parse_scan_result(
        parser_name="nuclei_json",
        output=nuclei_line,
        tool="nuclei",
        target="http://10.0.0.1",
        command="nuclei -u http://10.0.0.1",
    )
    assert isinstance(res_nuclei, ScanResult)
    assert len(res_nuclei.parsed_findings) == 1
    assert len(res_nuclei.findings) == 1
    assert res_nuclei.findings[0].severity == Severity.HIGH
    assert len(res_nuclei.parsed_hosts) == 0
