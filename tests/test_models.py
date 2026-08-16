import json
import pytest
from datetime import datetime

from rag.models import (
    AuditEntry,
    Campaign,
    CampaignState,
    CampaignStep,
    ExecutionResult,
    Finding,
    Host,
    Port,
    ScanResult,
    Service,
    Severity,
    StepState,
    ToolName,
    Verdict,
    Vulnerability,
    create_finding,
    from_json,
    normalize_severity,
    to_json,
    utc_now_iso,
)


# ── Enums & Severity Normalization Tests ──────────────────────────────────────

def test_severity_enum_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
    assert Severity.UNKNOWN.value == "unknown"


def test_normalize_severity():
    assert normalize_severity("CRITICAL") == Severity.CRITICAL
    assert normalize_severity("critical") == Severity.CRITICAL
    assert normalize_severity("crit") == Severity.CRITICAL
    assert normalize_severity("High") == Severity.HIGH
    assert normalize_severity("MEDIUM") == Severity.MEDIUM
    assert normalize_severity("med") == Severity.MEDIUM
    assert normalize_severity("low") == Severity.LOW
    assert normalize_severity("info") == Severity.INFO
    assert normalize_severity("informational") == Severity.INFO
    assert normalize_severity("none") == Severity.INFO
    assert normalize_severity("neglectable") == Severity.INFO
    assert normalize_severity("unknown") == Severity.UNKNOWN
    assert normalize_severity("something_else") == Severity.UNKNOWN
    assert normalize_severity(Severity.HIGH) == Severity.HIGH
    assert normalize_severity(None) == Severity.UNKNOWN
    assert normalize_severity(123) == Severity.UNKNOWN


def test_enums():
    assert CampaignState.PLANNING == "planning"
    assert CampaignState.RUNNING == "running"
    assert CampaignState.PAUSED == "paused"
    assert CampaignState.COMPLETED == "completed"
    assert CampaignState.FAILED == "failed"
    assert CampaignState.CANCELLED == "cancelled"

    assert StepState.PENDING == "pending"
    assert StepState.RUNNING == "running"
    assert StepState.COMPLETED == "completed"
    assert StepState.FAILED == "failed"
    assert StepState.SKIPPED == "skipped"
    assert StepState.BLOCKED == "blocked"

    assert Verdict.ALLOW == "allow"
    assert Verdict.WARN == "warn"
    assert Verdict.BLOCK == "block"

    assert ToolName.NMAP == "nmap"
    assert ToolName.NUCLEI == "nuclei"
    assert ToolName.FFUF == "ffuf"
    assert ToolName.SQLMAP == "sqlmap"
    assert ToolName.HYDRA == "hydra"
    assert ToolName.MASSCAN == "masscan"
    assert ToolName.AMASS == "amass"
    assert ToolName.GENERIC == "generic"


def test_utc_now_iso():
    ts = utc_now_iso()
    assert isinstance(ts, str)
    # Validate ISO-8601 parsing
    dt = datetime.fromisoformat(ts)
    assert dt is not None


# ── Service Model Tests ───────────────────────────────────────────────────────

def test_service_creation_and_dict():
    svc = Service(
        name="http",
        product="Apache httpd",
        version="2.4.49",
        extrainfo="(Ubuntu)",
        ostype="Linux",
        method="probed",
        conf=10,
        cpe=["cpe:/a:apache:http_server:2.4.49"],
        scripts=[{"id": "http-title", "output": "Welcome"}],
    )
    d = svc.to_dict()
    assert d["name"] == "http"
    assert d["product"] == "Apache httpd"
    assert d["version"] == "2.4.49"
    assert d["cpe"] == ["cpe:/a:apache:http_server:2.4.49"]

    svc2 = Service.from_dict(d)
    assert svc2.name == svc.name
    assert svc2.product == svc.product
    assert svc2.version == svc.version
    assert svc2.cpe == svc.cpe
    assert svc2.scripts == svc.scripts


def test_service_from_dict_with_dict_scripts():
    data = {
        "name": "ssh",
        "scripts": {"ssh-hostkey": "rsa1024", "banner": "OpenSSH 8.2"},
        "extra_junk": "ignore_me",
    }
    svc = Service.from_dict(data)
    assert svc.name == "ssh"
    assert len(svc.scripts) == 2
    assert any(s["id"] == "ssh-hostkey" for s in svc.scripts)


# ── Port Model Tests ──────────────────────────────────────────────────────────

def test_port_creation_and_properties():
    svc = Service(name="https", product="nginx", version="1.18.0")
    p = Port(
        number=443,
        protocol="tcp",
        state="open",
        service=svc,
        reason="syn-ack",
        reason_ttl=64,
    )
    assert p.number == 443
    assert p.port == 443
    assert p.protocol == "tcp"
    assert p.state == "open"
    assert p.service.name == "https"
    assert p.reason == "syn-ack"
    assert p.reason_ttl == 64

    # Test setter
    p.port = 8443
    assert p.number == 8443
    assert p.port == 8443

    d = p.to_dict()
    assert d["number"] == 8443
    assert d["port"] == 8443
    assert d["service"]["name"] == "https"

    p2 = Port.from_dict(d)
    assert p2.number == 8443
    assert p2.service.name == "https"
    assert p2.state == "open"


def test_port_alt_init():
    # Test init with port= kwarg and dict service
    p = Port(
        port=80,
        service={"name": "http", "product": "Apache"},
        scripts={"title": "Index of /"},
    )
    assert p.number == 80
    assert p.service is not None
    assert p.service.name == "http"
    assert len(p.scripts) == 1


# ── Host Model Tests ──────────────────────────────────────────────────────────

def test_host_creation_and_open_ports():
    p80 = Port(number=80, state="open", service=Service(name="http"))
    p443 = Port(number=443, state="open", service=Service(name="https"))
    p22 = Port(number=22, state="open", service=Service(name="ssh"))
    p23 = Port(number=23, state="closed")

    host = Host(
        address="192.168.1.10",
        hostnames=["web.local", "router.local"],
        ports=[p80, p443, p22, p23],
        os={"name": "Linux 5.4", "accuracy": "98"},
        status="up",
        distance=2,
    )
    assert host.address == "192.168.1.10"
    assert len(host.ports) == 4

    open_ports = host.open_ports()
    assert len(open_ports) == 3
    assert host.get_open_ports() == open_ports

    web_ports = host.web_ports()
    assert len(web_ports) == 2
    assert [p.number for p in web_ports] == [80, 443]

    d = host.to_dict()
    assert d["address"] == "192.168.1.10"
    assert len(d["ports"]) == 4

    host2 = Host.from_dict(d)
    assert host2.address == host.address
    assert len(host2.ports) == 4
    assert len(host2.open_ports()) == 3
    assert host2.hostnames == ["web.local", "router.local"]


# ── Finding & Vulnerability Model Tests ───────────────────────────────────────

def test_finding_creation_and_dedup_hash():
    f = Finding(
        tool="nuclei",
        vuln_type="cve-2021-44228",
        title="Log4j RCE",
        description="Apache Log4j JNDI RCE vulnerability",
        host="victim.local",
        port=8080,
        parameter="login",
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cve_ids=["CVE-2021-44228"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        tags=["cve", "rce", "log4j"],
        evidence={"matched_at": "http://victim.local:8080/login"},
    )
    assert f.tool == "nuclei"
    assert f.severity == Severity.CRITICAL
    assert f.target == "victim.local:8080"
    assert f.dedup_hash != ""
    old_hash = f.dedup_hash

    # Ensure compute_dedup_hash is deterministic
    new_hash = f.compute_dedup_hash()
    assert old_hash == new_hash

    d = f.to_dict()
    assert d["tool"] == "nuclei"
    assert d["severity"] == "critical"
    assert d["cvss_score"] == 10.0
    assert d["cve_ids"] == ["CVE-2021-44228"]

    f2 = Finding.from_dict(d)
    assert f2.id == f.id
    assert f2.tool == f.tool
    assert f2.vuln_type == f.vuln_type
    assert f2.severity == Severity.CRITICAL
    assert f2.dedup_hash == f.dedup_hash
    assert f2.cve_ids == ["CVE-2021-44228"]
    assert f2.evidence == {"matched_at": "http://victim.local:8080/login"}


def test_create_finding_factory():
    f = create_finding(
        tool=ToolName.SQLMAP,
        title="SQL Injection in id parameter",
        target="http://example.com/item?id=1",
        severity="critical",
        description="Boolean blind SQLi",
        evidence={"payload": "1 AND 1=1"},
        references=["https://owasp.org"],
        tags=["sqli", "injection"],
        host="example.com",
        port=80,
        vuln_type="sql_injection",
        parameter="id",
        cvss_score=9.8,
        cve_ids=["CVE-2022-1234"],
    )
    assert f.tool == "sqlmap"
    assert f.severity == Severity.CRITICAL
    assert f.host == "example.com"
    assert f.port == 80
    assert f.parameter == "id"
    assert f.cvss_score == 9.8
    assert f.cve_ids == ["CVE-2022-1234"]


def test_vulnerability_model():
    f = Finding(title="Weak TLS", host="example.com", severity=Severity.LOW)
    v = Vulnerability(
        finding=f,
        cve_id="CVE-2015-4000",
        cwe_id="CWE-310",
        title="Logjam Vulnerability",
        severity=Severity.MEDIUM,
        exploit_available=True,
        remediation="Disable weak DH ciphers",
    )
    assert v.cve_id == "CVE-2015-4000"
    assert v.exploit_available is True
    assert v.remediation == "Disable weak DH ciphers"

    d = v.to_dict()
    assert d["cve_id"] == "CVE-2015-4000"
    assert d["finding"]["title"] == "Weak TLS"

    v2 = Vulnerability.from_dict(d)
    assert v2.cve_id == "CVE-2015-4000"
    assert v2.finding is not None
    assert v2.finding.title == "Weak TLS"


# ── ScanResult Model Tests ────────────────────────────────────────────────────

def test_scan_result():
    host = Host(address="10.0.0.1")
    finding = Finding(title="Open Port", host="10.0.0.1", port=80)
    sr = ScanResult(
        tool="nmap",
        target="10.0.0.1",
        command="nmap 10.0.0.1",
        parsed_hosts=[host],
        parsed_findings=[finding],
        duration=2.5,
    )
    assert len(sr.hosts) == 1
    assert len(sr.findings) == 1
    assert sr.duration_seconds == 2.5

    f2 = Finding(title="Extra", host="10.0.0.1")
    sr.add_finding(f2)
    assert len(sr.findings) == 2

    h2 = Host(address="10.0.0.2")
    sr.add_host(h2)
    assert len(sr.hosts) == 2

    d = sr.to_dict()
    assert d["tool"] == "nmap"
    assert len(d["hosts"]) == 2
    assert len(d["findings"]) == 2

    sr2 = ScanResult.from_dict(d)
    assert sr2.tool == "nmap"
    assert len(sr2.hosts) == 2
    assert len(sr2.findings) == 2


# ── CampaignStep Model Tests ──────────────────────────────────────────────────

def test_campaign_step_render_command_and_dict():
    step = CampaignStep(
        id="step_nmap",
        tool="nmap",
        args=["-sV", "-T2", "-p", "{{open_ports}}", "{{target}}"],
        description="Service detection",
        depends_on=["step_recon"],
        condition="port 80 in open_ports",
    )
    ctx = {"target": "192.168.1.1", "open_ports": "80,443"}
    cmd_args = step.render_command(ctx)
    assert cmd_args == ["nmap", "-sV", "-T2", "-p", "80,443", "192.168.1.1"]

    d = step.to_dict()
    assert d["id"] == "step_nmap"
    assert d["tool"] == "nmap"
    assert d["state"] == "pending"
    assert d["condition"] == "port 80 in open_ports"

    step2 = CampaignStep.from_dict(d)
    assert step2.id == step.id
    assert step2.tool == step.tool
    assert step2.state == StepState.PENDING
    assert step2.depends_on == ["step_recon"]


def test_campaign_step_render_with_command_string():
    step = CampaignStep(
        id="raw_cmd",
        tool="generic",
        command="curl -k https://{{target}}/admin",
    )
    cmd_args = step.render_command({"target": "example.com"})
    assert cmd_args == ["curl", "-k", "https://example.com/admin"]


# ── ExecutionResult Model Tests ───────────────────────────────────────────────

def test_execution_result():
    res = ExecutionResult(
        step_id="step_1",
        tool="nuclei",
        target="example.com",
        command="nuclei -u example.com",
        success=True,
        return_code=0,
        duration=5.0,
        findings=[Finding(title="Exposed panel", host="example.com", severity=Severity.MEDIUM)],
        hosts=[Host(address="example.com")],
        raw_output="[INF] Found panel",
    )
    assert res.success is True
    assert res.duration_seconds == 5.0
    assert len(res.findings) == 1
    assert len(res.hosts) == 1

    d = res.to_dict()
    assert d["step_id"] == "step_1"
    assert d["success"] is True
    assert len(d["findings"]) == 1

    res2 = ExecutionResult.from_dict(d)
    assert res2.step_id == "step_1"
    assert res2.success is True
    assert len(res2.findings) == 1
    assert res2.findings[0].title == "Exposed panel"


# ── AuditEntry Model Tests ────────────────────────────────────────────────────

def test_audit_entry_json_line():
    entry = AuditEntry(
        operator="admin",
        campaign_id="camp_123",
        step_id="recon_nmap",
        event="step_completed",
        command="nmap -sV 10.0.0.1",
        verdict="allow",
        findings_count=3,
        duration=1.25,
        prev_hash="00000000",
        hash="abcdef123456",
        extra={"notes": "test audit"},
    )
    json_line = entry.to_json_line()
    assert isinstance(json_line, str)
    assert "camp_123" in json_line
    assert "step_completed" in json_line

    entry2 = AuditEntry.from_json_line(json_line)
    assert entry2.operator == "admin"
    assert entry2.campaign_id == "camp_123"
    assert entry2.step_id == "recon_nmap"
    assert entry2.findings_count == 3
    assert entry2.duration == 1.25
    assert entry2.hash == "abcdef123456"
    assert entry2.extra == {"notes": "test audit"}


# ── Campaign Model Tests ──────────────────────────────────────────────────────

def test_campaign_full_lifecycle():
    step1 = CampaignStep(id="recon_nmap", tool="nmap", args=["-sV", "{{target}}"])
    step2 = CampaignStep(id="recon_nuclei", tool="nuclei", args=["-u", "{{target}}"], depends_on=["recon_nmap"])
    campaign = Campaign(
        target="target.local",
        name="Target Assessment",
        description="Comprehensive pentest",
        steps=[step1, step2],
        state=CampaignState.PLANNING,
    )
    assert campaign.target == "target.local"
    assert len(campaign.steps) == 2
    assert campaign.state == CampaignState.PLANNING

    # Add finding and deduplication check
    f1 = Finding(vuln_type="sqli", title="SQLi in id", host="target.local", parameter="id", severity=Severity.CRITICAL, evidence={"payload": "1' OR '1'='1"})
    campaign.add_finding(f1)
    assert len(campaign.findings) == 1
    assert campaign.findings[0].campaign_id == campaign.id

    # Add duplicate finding - should merge evidence
    f1_dup = Finding(vuln_type="sqli", title="SQLi in id", host="target.local", parameter="id", severity=Severity.CRITICAL, evidence={"extra_key": "val"})
    campaign.add_finding(f1_dup)
    assert len(campaign.findings) == 1
    assert "extra_key" in campaign.findings[0].evidence

    # Add another finding
    f2 = Finding(vuln_type="info_leak", title="Server Banner", host="target.local", severity=Severity.INFO)
    campaign.add_finding(f2)
    assert len(campaign.findings) == 2

    # Query helpers
    crit_findings = campaign.get_findings_by_severity(Severity.CRITICAL)
    assert len(crit_findings) == 1
    assert crit_findings[0].title == "SQLi in id"

    high_crit = campaign.critical_high_findings()
    assert len(high_crit) == 1

    # Serialization
    d = campaign.to_dict()
    assert d["target"] == "target.local"
    assert d["state"] == "planning"
    assert len(d["steps"]) == 2
    assert len(d["findings"]) == 2

    camp2 = Campaign.from_dict(d)
    assert camp2.id == campaign.id
    assert camp2.target == campaign.target
    assert camp2.state == CampaignState.PLANNING
    assert len(camp2.steps) == 2
    assert len(camp2.findings) == 2


# ── Serialization Helper Tests ────────────────────────────────────────────────

def test_to_json_and_from_json():
    f = Finding(title="XSS Reflected", host="example.com", severity=Severity.HIGH)
    json_str = to_json(f)
    assert isinstance(json_str, str)
    assert "XSS Reflected" in json_str

    f_recovered = from_json(json_str, Finding)
    assert isinstance(f_recovered, Finding)
    assert f_recovered.title == "XSS Reflected"
    assert f_recovered.severity == Severity.HIGH
