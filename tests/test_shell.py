import os
import sys
from pathlib import Path
import pytest
import unittest.mock as mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rag.shell import OmniscienceShell
from rag.models import Campaign, CampaignState, StepState, Severity


@pytest.fixture
def test_shell(tmp_path, monkeypatch):
    """Fixture providing an OmniscienceShell operating in a temporary directory."""
    monkeypatch.chdir(tmp_path)
    shell = OmniscienceShell(config={}, dry_run=True, target="staging.local")
    return shell


def test_shell_init(test_shell):
    """Verify shell initializes with proper dry-run and subsystems."""
    assert test_shell.dry_run is True
    assert test_shell.current_target == "staging.local"
    assert test_shell.store is not None
    assert test_shell.finding_store is not None
    assert test_shell.audit_trail is not None
    assert test_shell.report_gen is not None
    assert test_shell.scope_guard is not None


def test_target_command(test_shell, capsys):
    """Test setting and viewing target."""
    test_shell.do_target("target.example.com")
    assert test_shell.current_target == "target.example.com"
    out = capsys.readouterr().out
    assert "Target set to: target.example.com" in out

    test_shell.do_target("")
    out = capsys.readouterr().out
    assert "Current target: target.example.com" in out


def test_plan_command(test_shell, capsys):
    """Test planning a campaign DAG without running it."""
    test_shell.do_plan("app.internal web_recon")
    assert test_shell.active_campaign_id is not None
    campaign = test_shell.store.load(test_shell.active_campaign_id)
    assert campaign is not None
    assert campaign.target == "app.internal"
    assert len(campaign.steps) == 3
    assert campaign.state == CampaignState.PLANNING
    out = capsys.readouterr().out
    assert "Campaign plan created" in out


def test_run_dry_run_full_dag(test_shell, capsys):
    """Test running a full campaign DAG in dry-run mode."""
    test_shell.do_run("vulnapp.local web_recon")
    assert test_shell.active_campaign_id is not None
    campaign = test_shell.store.load(test_shell.active_campaign_id)
    assert campaign is not None
    assert campaign.target == "vulnapp.local"
    assert campaign.state == CampaignState.COMPLETED

    # Verify all steps executed and succeeded in simulation
    for step in campaign.steps:
        st = step.state.value if isinstance(step.state, StepState) else str(step.state)
        assert st == "completed"
        assert step.result is not None
        assert step.result.success is True

    # Verify findings were added to campaign and finding store
    assert len(campaign.findings) > 0
    db_findings = test_shell.finding_store.list(campaign_id=campaign.id)
    assert len(db_findings) > 0

    out = capsys.readouterr().out
    assert "All campaign steps completed successfully" in out
    assert "CAMPAIGN SUMMARY" in out


def test_status_command(test_shell, capsys):
    """Test status display for active and all campaigns."""
    test_shell.do_run("status-test.local web_recon")
    capsys.readouterr()  # clear

    test_shell.do_status("")
    out = capsys.readouterr().out
    assert "CAMPAIGN STATUS" in out
    assert "status-test.local" in out
    assert "COMPLETED" in out


def test_findings_command(test_shell, capsys):
    """Test listing findings with and without filters."""
    test_shell.do_run("findings-test.local web_recon")
    capsys.readouterr()  # clear

    test_shell.do_findings("")
    out = capsys.readouterr().out
    assert "FINDINGS" in out

    test_shell.do_findings("high")
    out_high = capsys.readouterr().out
    assert "HIGH" in out_high or "No findings" in out_high or "FINDINGS" in out_high


def test_export_command_markdown_and_json(test_shell, capsys, tmp_path):
    """Test exporting campaign reports to Markdown and JSON files."""
    test_shell.do_run("export-test.local web_recon")
    capsys.readouterr()

    md_path = str(tmp_path / "report.md")
    test_shell.do_export(md_path)
    assert os.path.exists(md_path)
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "Security Assessment Report" in md_text

    json_path = str(tmp_path / "report.json")
    test_shell.do_export(json_path)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        json_text = f.read()
    assert "findings" in json_text


def test_audit_command_and_verification(test_shell, capsys):
    """Test audit log trail and chain integrity verification."""
    test_shell.do_run("audit-test.local web_recon")
    capsys.readouterr()

    test_shell.do_audit("")
    out = capsys.readouterr().out
    assert "AUDIT TRAIL INTEGRITY VERIFICATION" in out
    assert "VALID" in out
    assert "step_execution" in out


def test_step_command(test_shell, capsys):
    """Test executing a single step."""
    test_shell.do_plan("step-test.local web_recon")
    cid = test_shell.active_campaign_id
    capsys.readouterr()

    test_shell.do_step(cid)
    out = capsys.readouterr().out
    assert "Executing single step: recon_nmap" in out
    assert "Step completed" in out

    campaign = test_shell.store.load(cid)
    assert campaign.steps[0].state == StepState.COMPLETED
    assert campaign.steps[1].state == StepState.PENDING


def test_list_and_show_commands(test_shell, capsys):
    """Test list and show commands."""
    test_shell.do_plan("list-test.local web_recon")
    cid = test_shell.active_campaign_id
    capsys.readouterr()

    test_shell.do_list("")
    out_list = capsys.readouterr().out
    assert cid in out_list
    assert "list-test.local" in out_list

    test_shell.do_show(cid)
    out_show = capsys.readouterr().out
    assert "Campaign:" in out_show
    assert cid in out_show
    assert "recon_nmap" in out_show


def test_use_pause_resume_commands(test_shell, capsys):
    """Test use, pause, and resume commands."""
    test_shell.do_plan("pause-test.local web_recon")
    cid = test_shell.active_campaign_id
    capsys.readouterr()

    test_shell.do_use(cid)
    assert test_shell.active_campaign_id == cid
    out = capsys.readouterr().out
    assert "Active campaign set to" in out

    test_shell.do_pause(cid)
    camp = test_shell.store.load(cid)
    assert camp.state == CampaignState.PAUSED

    test_shell.do_resume(cid)
    camp_resumed = test_shell.store.load(cid)
    assert camp_resumed.state == CampaignState.COMPLETED


def test_tab_completions(test_shell):
    """Test auto-completion functions."""
    test_shell.do_plan("complete-test.local web_recon")
    cid = test_shell.active_campaign_id

    matches_show = test_shell.complete_show(cid[:3], f"show {cid[:3]}", 5, 8)
    assert cid in matches_show

    matches_run = test_shell.complete_run("web", "run web", 4, 7)
    assert "web_recon" in matches_run


def test_exit_and_quit_commands(test_shell):
    """Test clean exit handling."""
    assert test_shell.do_exit("") is True
    assert test_shell.do_quit("") is True
    assert test_shell.do_EOF("") is True
