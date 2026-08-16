import pytest
from pathlib import Path

from rag.findings import CampaignFindingManager, FindingStore, create_finding_store
from rag.models import Finding, Severity


@pytest.fixture
def finding_store(tmp_path):
    db_file = tmp_path / "test_findings.db"
    return FindingStore(str(db_file))


# ── CRUD Operation Tests ──────────────────────────────────────────────────────

def test_add_and_get_finding(finding_store):
    f = Finding(
        campaign_id="camp_01",
        step_id="step_nmap",
        tool="nmap",
        vuln_type="open_port",
        title="Open Port 80 HTTP",
        description="Apache httpd 2.4.41",
        host="192.168.1.1",
        port=80,
        parameter="http",
        evidence={"banner": "Apache/2.4.41"},
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_score=5.3,
        severity=Severity.MEDIUM,
        cve_ids=["CVE-2021-1234"],
        references=["https://nvd.nist.gov"],
        tags=["web", "http"],
        status="open",
    )
    added = finding_store.add(f)
    assert added is True

    fetched = finding_store.get(f.id)
    assert fetched is not None
    assert fetched.id == f.id
    assert fetched.campaign_id == "camp_01"
    assert fetched.tool == "nmap"
    assert fetched.severity == Severity.MEDIUM
    assert fetched.cvss_score == 5.3
    assert fetched.evidence == {"banner": "Apache/2.4.41"}
    assert fetched.cve_ids == ["CVE-2021-1234"]
    assert fetched.tags == ["web", "http"]


def test_get_nonexistent_finding(finding_store):
    assert finding_store.get("non_existent_id") is None


def test_update_finding(finding_store):
    f = Finding(
        campaign_id="camp_01",
        tool="nuclei",
        vuln_type="cve",
        title="Original Title",
        host="10.0.0.1",
        severity=Severity.LOW,
    )
    finding_store.add(f)

    f.title = "Updated Title"
    f.severity = Severity.HIGH
    f.status = "remediated"
    updated = finding_store.update(f)
    assert updated is True

    fetched = finding_store.get(f.id)
    assert fetched.title == "Updated Title"
    assert fetched.severity == Severity.HIGH
    assert fetched.status == "remediated"


def test_delete_finding(finding_store):
    f = Finding(campaign_id="camp_01", tool="ffuf", vuln_type="discovery", title="Found /admin", host="10.0.0.1")
    finding_store.add(f)
    assert finding_store.get(f.id) is not None

    deleted = finding_store.delete(f.id)
    assert deleted is True
    assert finding_store.get(f.id) is None

    # Deleting non-existent returns False
    assert finding_store.delete("non_existent_id") is False


# ── Deduplication Tests ───────────────────────────────────────────────────────

def test_deduplication_merges_evidence(finding_store):
    f1 = Finding(
        campaign_id="camp_01",
        tool="nmap",
        vuln_type="sqli",
        title="SQL Injection",
        host="example.com",
        port=80,
        parameter="id",
        severity=Severity.HIGH,
        evidence={"first_scan": True, "info": "initial"},
    )
    finding_store.add(f1)

    # Identical dedup attributes, new evidence
    f2 = Finding(
        campaign_id="camp_01",
        tool="sqlmap",
        vuln_type="sqli",
        title="SQL Injection",
        host="example.com",
        port=80,
        parameter="id",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        evidence={"second_scan": True, "payload": "1' OR '1'='1'"},
    )
    finding_store.add(f2)

    # Should have only 1 finding in database with merged evidence
    all_findings = finding_store.list()
    assert len(all_findings) == 1
    merged = all_findings[0]
    assert merged.severity == Severity.CRITICAL
    assert merged.cvss_score == 9.8
    assert merged.evidence.get("first_scan") is True
    assert merged.evidence.get("second_scan") is True
    assert merged.evidence.get("payload") == "1' OR '1'='1'"


# ── Query Filtering Tests ─────────────────────────────────────────────────────

def test_list_query_filters(finding_store):
    finding_store.add(Finding(campaign_id="c1", tool="nmap", host="10.0.0.1", severity=Severity.LOW, status="open"))
    finding_store.add(Finding(campaign_id="c1", tool="nuclei", host="10.0.0.1", severity=Severity.HIGH, status="open"))
    finding_store.add(Finding(campaign_id="c2", tool="nuclei", host="10.0.0.2", severity=Severity.CRITICAL, status="closed"))

    # Campaign filter
    c1_list = finding_store.list(campaign_id="c1")
    assert len(c1_list) == 2

    # Severity filter (enum and string)
    crit_list = finding_store.list(severity=Severity.CRITICAL)
    assert len(crit_list) == 1
    assert crit_list[0].campaign_id == "c2"

    high_list = finding_store.list(severity="high")
    assert len(high_list) == 1

    # Status filter
    open_list = finding_store.list(status="open")
    assert len(open_list) == 2

    # Host filter
    host_list = finding_store.list(host="10.0.0.2")
    assert len(host_list) == 1

    # Tool filter
    nuclei_list = finding_store.list(tool="nuclei")
    assert len(nuclei_list) == 2

    # Limit
    limited = finding_store.list(limit=1)
    assert len(limited) == 1


# ── Statistics Tests ──────────────────────────────────────────────────────────

def test_get_stats(finding_store):
    finding_store.add(Finding(campaign_id="c1", tool="nmap", severity=Severity.LOW, status="open"))
    finding_store.add(Finding(campaign_id="c1", tool="nmap", severity=Severity.HIGH, status="open"))
    finding_store.add(Finding(campaign_id="c1", tool="nuclei", severity=Severity.CRITICAL, status="closed"))
    finding_store.add(Finding(campaign_id="c2", tool="nuclei", severity=Severity.MEDIUM, status="open"))

    # Overall stats
    stats = finding_store.get_stats()
    assert stats["total"] == 4
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["medium"] == 1
    assert stats["by_severity"]["low"] == 1
    assert stats["by_tool"]["nmap"] == 2
    assert stats["by_tool"]["nuclei"] == 2
    assert stats["by_status"]["open"] == 3
    assert stats["by_status"]["closed"] == 1

    # Campaign specific stats
    c1_stats = finding_store.get_stats(campaign_id="c1")
    assert c1_stats["total"] == 3
    assert c1_stats["by_severity"]["critical"] == 1
    assert c1_stats["by_tool"]["nmap"] == 2


# ── CampaignFindingManager Tests ──────────────────────────────────────────────

def test_campaign_finding_manager(finding_store):
    mgr = CampaignFindingManager(store=finding_store, campaign_id="camp_managed")

    mgr.add_finding(Finding(title="Crit 1", severity=Severity.CRITICAL, host="10.0.0.1"))
    mgr.add_finding(Finding(title="High 1", severity=Severity.HIGH, host="10.0.0.1"))
    mgr.add_finding(Finding(title="Low 1", severity=Severity.LOW, host="10.0.0.1"))

    findings = mgr.get_findings()
    assert len(findings) == 3
    assert all(f.campaign_id == "camp_managed" for f in findings)

    crit_high = mgr.get_critical_high()
    assert len(crit_high) == 2
    assert any(f.title == "Crit 1" for f in crit_high)
    assert any(f.title == "High 1" for f in crit_high)

    stats = mgr.get_stats()
    assert stats["total"] == 3


def test_create_finding_store_factory(tmp_path):
    store = create_finding_store(str(tmp_path / "factory_findings.db"))
    assert isinstance(store, FindingStore)
    assert store.get_stats()["total"] == 0
