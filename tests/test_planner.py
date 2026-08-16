import pytest
from pathlib import Path
from rag.models import Campaign, CampaignStep, StepState, Host, Port, Finding, ScanResult, ExecutionResult
from rag.planner import (
    CAMPAIGN_TEMPLATES,
    list_templates,
    get_template,
    create_campaign_from_template,
    create_campaign,
    build_context,
    check_step_conditions,
    get_next_pending_steps,
    resolve_step_args,
    load_templates,
)


def test_list_templates():
    templates = list_templates()
    # Should discover built-ins and YAML files from templates/
    assert "web_recon" in templates
    assert "infra_recon" in templates
    assert "ad_enum" in templates
    assert "mobile_recon" in templates


def test_get_template():
    template = get_template("web_recon")
    assert template["name"] == "Web Application Reconnaissance"
    assert len(template["steps"]) == 3

    # Unknown template returns empty dict
    assert get_template("non_existent_template") == {}


def test_get_template_case_insensitive_and_by_name():
    template = get_template("WEB_RECON")
    assert template["name"] == "Web Application Reconnaissance"

    template_by_name = get_template("Web Application Reconnaissance")
    assert template_by_name["name"] == "Web Application Reconnaissance"


def test_fallback_without_yaml_dir(tmp_path):
    # Empty directory fallback
    empty_dir = tmp_path / "empty_templates"
    empty_dir.mkdir()
    templates = load_templates(template_dir=empty_dir)
    assert "web_recon" in templates
    assert "infra_recon" in templates


def test_create_campaign():
    campaign = create_campaign("example.com", "web_recon")
    assert isinstance(campaign, Campaign)
    assert campaign.target == "example.com"
    assert campaign.name == "Web Application Reconnaissance"
    assert len(campaign.steps) == 3
    assert campaign.steps[0].id == "recon_nmap"
    assert campaign.steps[0].target == "example.com"


def test_create_campaign_from_template_with_kwargs():
    campaign = create_campaign_from_template(
        "ad_enum",
        target="10.0.0.1",
        username="admin",
        password="Password123!",
        domain="CORP.LOCAL",
    )
    assert campaign.target == "10.0.0.1"
    assert campaign.metadata.get("username") == "admin"
    assert campaign.metadata.get("domain") == "CORP.LOCAL"


def test_create_campaign_unknown_template_raises():
    with pytest.raises(ValueError, match="Unknown template"):
        create_campaign_from_template("invalid_template", "example.com")


def test_build_context_from_scan_results():
    campaign = create_campaign("example.com", "web_recon")
    
    # Simulate nmap ScanResult with open ports 80 and 443
    host = Host(
        address="192.168.1.50",
        ports=[
            Port(80, state="open"),
            Port(443, state="open"),
            Port(22, state="open"),
            Port(8080, state="closed"),
        ]
    )
    scan_result = ScanResult(
        tool="nmap",
        target="example.com",
        parsed_hosts=[host],
        parsed_findings=[
            Finding(vuln_type="subdomain_enumeration", host="api.example.com", tool="amass")
        ]
    )
    step_results = {"recon_nmap": scan_result}
    
    ctx = build_context(campaign, step_results)
    assert ctx["target"] == "example.com"
    assert "80" in ctx["open_ports"]
    assert "443" in ctx["open_ports"]
    assert "22" in ctx["open_ports"]
    assert "8080" not in ctx["open_ports"]
    assert "80" in ctx["open_web_ports"]
    assert "443" in ctx["open_web_ports"]
    assert "22" not in ctx["open_web_ports"]
    assert "api.example.com" in ctx["subdomains"]
    assert "80" in ctx["open_ports_str"]


def test_build_context_from_dict_and_metadata():
    campaign = create_campaign_from_template(
        "ad_enum",
        target="10.0.0.5",
        username="john",
        password="secretpassword",
        domain="contoso.com",
    )
    step_results = {
        "recon_nmap": {
            "state": "completed",
            "open_ports": ["88", "389", "445"],
        }
    }
    ctx = build_context(campaign, step_results)
    assert ctx["target"] == "10.0.0.5"
    assert ctx["username"] == "john"
    assert ctx["password"] == "secretpassword"
    assert ctx["domain"] == "contoso.com"
    assert "88" in ctx["open_ports"]
    assert "389" in ctx["open_ports"]
    assert "445" in ctx["open_ports"]
    assert ctx["open_ports_str"] == "389,445,88" or "88" in ctx["open_ports_str"]


def test_check_step_conditions():
    step_with_or = CampaignStep(
        id="recon_ffuf",
        tool="ffuf",
        condition="port 80 in open_ports or port 443 in open_ports",
    )
    step_with_and = CampaignStep(
        id="step_and",
        tool="nuclei",
        condition="port 80 in open_ports and port 443 in open_ports",
    )
    step_no_cond = CampaignStep(id="recon_nmap", tool="nmap")

    # Only port 80 open
    ctx_80 = {"open_ports": ["80"]}
    assert check_step_conditions(step_with_or, ctx_80) is True
    assert check_step_conditions(step_with_and, ctx_80) is False
    assert check_step_conditions(step_no_cond, ctx_80) is True

    # Only port 443 open
    ctx_443 = {"open_ports": ["443"]}
    assert check_step_conditions(step_with_or, ctx_443) is True
    assert check_step_conditions(step_with_and, ctx_443) is False

    # Both 80 and 443 open
    ctx_both = {"open_ports": ["80", "443"]}
    assert check_step_conditions(step_with_or, ctx_both) is True
    assert check_step_conditions(step_with_and, ctx_both) is True

    # Only port 22 open
    ctx_22 = {"open_ports": ["22"]}
    assert check_step_conditions(step_with_or, ctx_22) is False
    assert check_step_conditions(step_with_and, ctx_22) is False


def test_get_next_pending_steps_web_recon():
    campaign = create_campaign("example.com", "web_recon")
    
    # 1. Initially only root step (recon_nmap) should be ready
    pending = get_next_pending_steps(campaign, {})
    assert pending == ["recon_nmap"]

    # 2. Once recon_nmap completes with port 80, both nuclei and ffuf should be ready
    step_results_web = {
        "recon_nmap": {
            "state": "completed",
            "open_ports": ["80"],
            "open_web_ports": ["80"],
        }
    }
    pending = get_next_pending_steps(campaign, step_results_web)
    assert "recon_nuclei" in pending
    assert "recon_ffuf" in pending

    # 3. Once recon_nmap completes with ONLY port 22 (SSH), ffuf is not ready (condition fails)
    step_results_ssh = {
        "recon_nmap": {
            "state": "completed",
            "open_ports": ["22"],
            "open_web_ports": [],
        }
    }
    pending_ssh = get_next_pending_steps(campaign, step_results_ssh)
    assert "recon_nuclei" in pending_ssh
    assert "recon_ffuf" not in pending_ssh


def test_resolve_step_args():
    step_nmap = CampaignStep(
        id="recon_nmap",
        tool="nmap",
        args=["-sV", "-T2", "-oX", "-", "{{target}}"],
    )
    ctx = {"target": "10.0.0.1"}
    argv = resolve_step_args(step_nmap, ctx)
    assert argv == ["nmap", "-sV", "-T2", "-oX", "-", "10.0.0.1"]

    step_infra = CampaignStep(
        id="recon_nmap_infra",
        tool="nmap",
        args=["-sV", "-T2", "-p", "{{open_ports}}", "-oX", "-", "{{target}}"],
    )
    ctx_infra = {"target": "192.168.1.10", "open_ports": ["80", "443"]}
    argv_infra = resolve_step_args(step_infra, ctx_infra)
    assert argv_infra == ["nmap", "-sV", "-T2", "-p", "80,443", "-oX", "-", "192.168.1.10"] or argv_infra == ["nmap", "-sV", "-T2", "-p", "443,80", "-oX", "-", "192.168.1.10"]

    step_ad = CampaignStep(
        id="bloodhound",
        tool="bloodhound-python",
        args=["-u", "{{username}}", "-p", "{{password}}", "-ns", "{{target}}", "-d", "{{domain}}", "-c", "All", "--zip"],
    )
    ctx_ad = {
        "target": "10.0.0.1",
        "username": "admin",
        "password": "Password123!",
        "domain": "CORP.LOCAL",
    }
    argv_ad = resolve_step_args(step_ad, ctx_ad)
    assert argv_ad == [
        "bloodhound-python",
        "-u", "admin",
        "-p", "Password123!",
        "-ns", "10.0.0.1",
        "-d", "CORP.LOCAL",
        "-c", "All",
        "--zip",
    ]
