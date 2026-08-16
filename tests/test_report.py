import json
import pytest

from rag.findings import FindingStore
from rag.models import Campaign, Finding, Severity
from rag.report import ReportGenerator, create_report_generator


@pytest.fixture
def populated_store(tmp_path):
    store = FindingStore(str(tmp_path / "report_findings.db"))
    store.add(
        Finding(
            campaign_id="camp_report",
            tool="nuclei",
            vuln_type="cve-2021-44228",
            title="Log4j Remote Code Execution",
            description="Critical RCE vulnerability in Apache Log4j",
            host="app.example.com",
            port=8080,
            parameter="login",
            evidence={"matched_at": "http://app.example.com:8080/login", "extracted": "jndi:ldap"},
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            severity=Severity.CRITICAL,
            cve_ids=["CVE-2021-44228"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            status="open",
        )
    )
    store.add(
        Finding(
            campaign_id="camp_report",
            tool="ffuf",
            vuln_type="directory_discovery",
            title="Admin Console Exposed",
            description="Exposed administrative interface",
            host="app.example.com",
            port=8080,
            parameter="/admin",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            status="open",
        )
    )
    return store


@pytest.fixture
def populated_campaign():
    f1 = Finding(
        campaign_id="camp_obj",
        tool="sqlmap",
        vuln_type="sql_injection",
        title="SQL Injection in id parameter",
        description="Boolean blind SQL injection",
        host="db.example.com",
        port=3306,
        parameter="id",
        evidence={"payload": "1' AND 1=1"},
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2022-9999"],
        references=["https://owasp.org"],
        status="open",
    )
    f2 = Finding(
        campaign_id="camp_obj",
        tool="nmap",
        vuln_type="info_leak",
        title="TLS Certificate Expiration",
        description="TLS cert expires within 7 days",
        host="db.example.com",
        port=443,
        severity=Severity.LOW,
        cvss_score=3.1,
        status="open",
    )
    campaign = Campaign(
        id="camp_obj",
        target="db.example.com",
        name="Database Penetration Test",
        findings=[f1, f2],
    )
    return campaign


# ── Markdown Generation Tests ─────────────────────────────────────────────────

def test_generate_markdown_from_store(populated_store):
    gen = ReportGenerator(populated_store)
    md = gen.generate_markdown(campaign_id="camp_report")

    assert "# Security Assessment Report" in md
    assert "camp_report" in md
    assert "Executive Summary" in md
    assert "Critical" in md
    assert "Log4j Remote Code Execution" in md
    assert "Admin Console Exposed" in md
    assert "CVE-2021-44228" in md
    assert "CVSS:3.1" in md
    assert "```json" in md  # Evidence code block


def test_generate_markdown_from_campaign_object(populated_campaign):
    gen = ReportGenerator()
    md = gen.generate_markdown(campaign=populated_campaign)

    assert "# Security Assessment Report" in md
    assert "camp_obj" in md
    assert "db.example.com" in md
    assert "SQL Injection in id parameter" in md
    assert "TLS Certificate Expiration" in md
    assert "CVE-2022-9999" in md


def test_generate_markdown_empty_findings(tmp_path):
    empty_store = FindingStore(str(tmp_path / "empty_report.db"))
    gen = ReportGenerator(empty_store)
    md = gen.generate_markdown(campaign_id="non_existent")

    assert "# Security Assessment Report" in md
    assert "No security vulnerabilities or findings were identified" in md
    assert "No detailed findings to report" in md


# ── JSON Export Tests ─────────────────────────────────────────────────────────

def test_export_findings_json_from_store(populated_store):
    gen = ReportGenerator(populated_store)
    json_str = gen.export_findings_json(campaign_id="camp_report")

    data = json.loads(json_str)
    assert data["campaign_id"] == "camp_report"
    assert "stats" in data
    assert data["stats"]["total"] == 2
    assert len(data["findings"]) == 2

    titles = [f["title"] for f in data["findings"]]
    assert "Log4j Remote Code Execution" in titles
    assert "Admin Console Exposed" in titles


def test_export_findings_json_from_campaign(populated_campaign):
    gen = ReportGenerator()
    json_str = gen.export_findings_json(campaign=populated_campaign)

    data = json.loads(json_str)
    assert data["campaign_id"] == "camp_obj"
    assert data["target"] == "db.example.com"
    assert data["stats"]["total"] == 2
    assert len(data["findings"]) == 2


# ── Factory Helper Tests ──────────────────────────────────────────────────────

def test_create_report_generator_factory():
    gen = create_report_generator()
    assert isinstance(gen, ReportGenerator)
    assert gen.store is None
