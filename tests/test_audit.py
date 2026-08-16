import json
import pytest
from pathlib import Path

from rag.audit import AuditTrail, GENESIS_HASH, create_audit_trail


@pytest.fixture
def audit_log(tmp_path):
    log_file = tmp_path / "test_audit.log"
    return AuditTrail(str(log_file))


# ── Initialization & Basic Logging Tests ─────────────────────────────────────

def test_audit_init_genesis(audit_log):
    assert audit_log._last_hash == GENESIS_HASH


def test_audit_log_single_entry(audit_log):
    h1 = audit_log.log(
        event="step_started",
        operator="kali_user",
        campaign_id="camp_01",
        step_id="recon_nmap",
        command="nmap -sV 10.0.0.1",
        verdict="allow",
        duration=0.5,
    )
    assert len(h1) == 64
    assert audit_log._last_hash == h1

    # Verify written content
    entries = audit_log.query(limit=10)
    assert len(entries) == 1
    assert entries[0]["hash"] == h1
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[0]["event"] == "step_started"
    assert entries[0]["operator"] == "kali_user"


# ── Hash Chaining Tests ───────────────────────────────────────────────────────

def test_audit_hash_chain_multiple_entries(audit_log):
    h1 = audit_log.log(event="e1", campaign_id="c1", step_id="s1")
    h2 = audit_log.log(event="e2", campaign_id="c1", step_id="s2")
    h3 = audit_log.log(event="e3", campaign_id="c1", step_id="s3")

    entries = audit_log.query(limit=10)  # Most recent first: e3, e2, e1
    assert len(entries) == 3

    assert entries[0]["hash"] == h3
    assert entries[0]["prev_hash"] == h2

    assert entries[1]["hash"] == h2
    assert entries[1]["prev_hash"] == h1

    assert entries[2]["hash"] == h1
    assert entries[2]["prev_hash"] == GENESIS_HASH


# ── Query Filtering Tests ─────────────────────────────────────────────────────

def test_audit_query_filters(audit_log):
    audit_log.log(event="start", operator="alice", campaign_id="c1")
    audit_log.log(event="scan", operator="alice", campaign_id="c1")
    audit_log.log(event="scan", operator="bob", campaign_id="c2")
    audit_log.log(event="finish", operator="bob", campaign_id="c2")

    # Filter by campaign
    c1_entries = audit_log.query(campaign_id="c1")
    assert len(c1_entries) == 2
    assert all(e["campaign_id"] == "c1" for e in c1_entries)

    # Filter by operator
    alice_entries = audit_log.query(operator="alice")
    assert len(alice_entries) == 2
    assert all(e["operator"] == "alice" for e in alice_entries)

    # Filter by event
    scan_entries = audit_log.query(event="scan")
    assert len(scan_entries) == 2
    assert all(e["event"] == "scan" for e in scan_entries)

    # Limit
    limited = audit_log.query(limit=2)
    assert len(limited) == 2


# ── Chain Verification & Tamper Detection Tests ───────────────────────────────

def test_verify_chain_valid(audit_log):
    for i in range(5):
        audit_log.log(event=f"step_{i}", command=f"cmd_{i}")

    result = audit_log.verify_chain()
    assert result["valid"] is True
    assert result["entries_checked"] == 5
    assert len(result["errors"]) == 0


def test_verify_chain_empty(tmp_path):
    empty_trail = AuditTrail(str(tmp_path / "empty.log"))
    res = empty_trail.verify_chain()
    assert res["valid"] is True
    assert res["entries_checked"] == 0
    assert len(res["errors"]) == 0


def test_verify_chain_detects_content_tampering(audit_log):
    audit_log.log(event="step_1", command="nmap 10.0.0.1")
    audit_log.log(event="step_2", command="nuclei 10.0.0.1")
    audit_log.log(event="step_3", command="ffuf 10.0.0.1")

    # Tamper with the 2nd line's command without updating hash
    log_path = audit_log.log_path
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entry2 = json.loads(lines[1])
    entry2["command"] = "malicious_tampered_command 10.0.0.1"
    lines[1] = json.dumps(entry2) + "\n"

    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    res = audit_log.verify_chain()
    assert res["valid"] is False
    assert len(res["errors"]) > 0
    assert any("Hash mismatch" in err["error"] for err in res["errors"])


def test_verify_chain_detects_broken_link(audit_log):
    audit_log.log(event="step_1")
    audit_log.log(event="step_2")
    audit_log.log(event="step_3")

    # Tamper with prev_hash link on line 2
    log_path = audit_log.log_path
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entry2 = json.loads(lines[1])
    entry2["prev_hash"] = "0" * 64
    lines[1] = json.dumps(entry2) + "\n"

    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    res = audit_log.verify_chain()
    assert res["valid"] is False
    assert any("Hash chain broken" in err["error"] for err in res["errors"])


def test_verify_chain_detects_malformed_json(audit_log):
    audit_log.log(event="step_1")
    log_path = audit_log.log_path
    with open(log_path, "a", encoding="utf-8") as f:
        f.write("corrupted non json line\n")

    res = audit_log.verify_chain()
    assert res["valid"] is False
    assert any("JSON decode error" in err["error"] for err in res["errors"])


def test_create_audit_trail_factory(tmp_path):
    trail = create_audit_trail(str(tmp_path / "factory_audit.log"))
    assert isinstance(trail, AuditTrail)
    h = trail.log("test_event")
    assert len(h) == 64
