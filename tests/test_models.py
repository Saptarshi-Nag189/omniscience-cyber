import pytest
from rag.models import Campaign, CampaignStep, Severity, Finding

def test_campaign_creation():
    step = CampaignStep(id="test_step", tool="nmap", args=["-sV"])
    campaign = Campaign(target="example.com", name="Test", steps=[step])
    assert campaign.target == "example.com"
    assert len(campaign.steps) == 1
    assert campaign.steps[0].id == "test_step"
