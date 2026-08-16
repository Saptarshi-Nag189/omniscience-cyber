from __future__ import annotations

"""
rag/state.py — Campaign state persistence and execution runtime.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    Campaign,
    CampaignState,
    CampaignStep,
    ExecutionResult,
    Finding,
    StepState,
    utc_now_iso,
)

logger = logging.getLogger(__name__)


class CampaignStateStore:
    """Persists campaigns to JSON files in the campaign directory."""

    def __init__(self, storage_dir: str = "campaigns"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _campaign_path(self, campaign_id: str) -> Path:
        return self.storage_dir / f"{campaign_id}.json"

    def save(self, campaign: Campaign) -> None:
        campaign.updated_at = utc_now_iso()
        data = campaign.to_dict()
        with open(self._campaign_path(campaign.id), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def load(self, campaign_id: str) -> Optional[Campaign]:
        path = self._campaign_path(campaign_id)
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return Campaign.from_dict(data)

    def delete(self, campaign_id: str) -> bool:
        path = self._campaign_path(campaign_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list(self) -> List[Dict[str, Any]]:
        campaigns = []
        for path in self.storage_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                campaigns.append({
                    "id": data.get("id"),
                    "target": data.get("target"),
                    "name": data.get("name"),
                    "state": data.get("state"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "findings_count": len(data.get("findings", [])),
                })
            except Exception:
                pass
        return sorted(campaigns, key=lambda x: str(x.get("updated_at", "")), reverse=True)


class CampaignRuntime:
    """Manages active execution lifecycle and step state transitions for a campaign."""

    def __init__(self, store: CampaignStateStore, campaign_id: str):
        self.store = store
        self.campaign_id = campaign_id
        self.campaign = store.load(campaign_id)
        if not self.campaign:
            raise ValueError(f"Campaign {campaign_id} not found")

    def update_step(self, step_id: str, result: ExecutionResult) -> None:
        for step in self.campaign.steps:
            if step.id == step_id:
                step.state = StepState.COMPLETED if result.success else StepState.FAILED
                step.result = result
                step.completed_at = utc_now_iso()
                break

        # Add findings to campaign
        for finding in result.findings:
            self.campaign.add_finding(finding)

        self.campaign.updated_at = utc_now_iso()
        self.campaign.state = CampaignState.RUNNING
        self.store.save(self.campaign)

    def mark_blocked(self, step_id: str, reason: str) -> None:
        for step in self.campaign.steps:
            if step.id == step_id:
                step.state = StepState.BLOCKED
                step.completed_at = utc_now_iso()
                step.evidence = {"block_reason": reason}
                break
        self.campaign.updated_at = utc_now_iso()
        self.store.save(self.campaign)

    def get_next_steps(self) -> List[str]:
        from .planner import get_next_pending_steps
        step_results = {}
        for s in self.campaign.steps:
            if s.result:
                step_results[s.id] = s.result
        return get_next_pending_steps(self.campaign, step_results)

    def mark_completed(self) -> None:
        self.campaign.state = CampaignState.COMPLETED
        self.campaign.completed_at = utc_now_iso()
        self.campaign.updated_at = utc_now_iso()
        self.store.save(self.campaign)

    def mark_failed(self, reason: str) -> None:
        self.campaign.state = CampaignState.FAILED
        self.campaign.metadata["failure_reason"] = reason
        self.campaign.updated_at = utc_now_iso()
        self.store.save(self.campaign)


def create_campaign_store(storage_dir: str = "campaigns") -> CampaignStateStore:
    return CampaignStateStore(storage_dir)
