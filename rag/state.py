from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

from .models import Campaign, CampaignStep, CampaignState, StepState, ExecutionResult, Finding


class CampaignStateStore:
    def __init__(self, storage_dir: str = 'campaigns'):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def _campaign_path(self, campaign_id: str) -> Path:
        return self.storage_dir / f'{campaign_id}.json'
    
    def save(self, campaign: Campaign) -> None:
        campaign.updated_at = datetime.utcnow().isoformat()
        data = campaign.to_dict()
        with open(self._campaign_path(campaign.id), 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def load(self, campaign_id: str) -> Optional[Campaign]:
        path = self._campaign_path(campaign_id)
        if not path.exists():
            return None
        with open(path, 'r') as f:
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
        for path in self.storage_dir.glob('*.json'):
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                campaigns.append({
                    'id': data.get('id'),
                    'target': data.get('target'),
                    'name': data.get('name'),
                    'state': data.get('state'),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at'),
                    'findings_count': len(data.get('findings', [])),
                })
            except Exception:
                pass
        return sorted(campaigns, key=lambda x: x.get('updated_at', ''), reverse=True)


class CampaignRuntime:
    def __init__(self, store: CampaignStateStore, campaign_id: str):
        self.store = store
        self.campaign_id = campaign_id
        self.campaign = store.load(campaign_id)
        if not self.campaign:
            raise ValueError(f'Campaign {campaign_id} not found')
    
    def update_step(self, step_id: str, result: ExecutionResult) -> None:
        for step in self.campaign.steps:
            if step.id == step_id:
                step.state = 'completed' if result.success else 'failed'
                step.result = result.state
                step.completed_at = datetime.utcnow().isoformat()
                break
        
        # Add findings to campaign
        for finding in result.findings:
            self.campaign.add_finding(finding)
        
        self.campaign.updated_at = datetime.utcnow().isoformat()
        self.campaign.state = 'running'
        self.store.save(self.campaign)
    
    def mark_blocked(self, step_id: str, reason: str) -> None:
        for step in self.campaign.steps:
            if step.id == step_id:
                step.state = 'blocked'
                step.completed_at = datetime.utcnow().isoformat()
                step.evidence = {'block_reason': reason}
                break
        self.store.save(self.campaign)
    
    def get_next_steps(self) -> List[str]:
        from .planner import get_next_pending_steps, build_context
        context = build_context(self.campaign, {s.id: s.result for s in self.campaign.steps if s.result})
        from .planner import get_next_pending_steps
        return get_next_pending_steps(self.campaign, {s.id: s.result for s in self.campaign.steps if s.result})
    
    def mark_completed(self) -> None:
        self.campaign.state = 'completed'
        self.campaign.completed_at = datetime.utcnow().isoformat()
        self.store.save(self.campaign)
    
    def mark_failed(self, reason: str) -> None:
        self.campaign.state = 'failed'
        self.campaign.metadata['failure_reason'] = reason
        self.store.save(self.campaign)

def create_campaign_store(storage_dir: str = 'campaigns') -> CampaignStateStore:
    return CampaignStateStore(storage_dir)
