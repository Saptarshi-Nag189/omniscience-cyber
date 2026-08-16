import pytest
from rag.planner import get_template, list_templates

def test_list_templates():
    templates = list_templates()
    assert "web_recon" in templates
    assert "infra_recon" in templates

def test_get_template():
    template = get_template("web_recon")
    assert template["name"] == "Web Application Reconnaissance"
    assert len(template["steps"]) == 3
