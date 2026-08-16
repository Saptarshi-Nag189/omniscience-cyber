#!/usr/bin/env python3
"""
omniscience-shell - Interactive REPL for omniscience-cyber campaigns.
"""

from __future__ import annotations

import argparse
import asyncio
import cmd
import json
import os
import readline
import shlex
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from .models import Campaign, CampaignStep, CampaignState, StepState, Severity
from .state import CampaignStateStore, CampaignRuntime
from .planner import create_campaign_from_template, get_next_pending_steps, build_context
from .executor import KaliExecutor, ExecutorConfig
from .scope_guard import ScopeGuard
from .findings import create_finding_store
class OmniscienceShell(cmd.Cmd):
    """Interactive REPL for omniscience-cyber."""

    intro = textwrap.dedent("""
        Commands:
          run <target> [template]     - Create and run a new campaign
          plan <target> [template]    - Create campaign plan without executing
          list                        - List all campaigns
          show <campaign_id>          - Show campaign details
          findings <campaign_id>      - Show campaign findings
          export <campaign_id> [fmt]  - Export report (md/html/json)
          step <campaign_id>          - Execute next step(s) in campaign
          pause <campaign_id>         - Pause running campaign
          resume <campaign_id>        - Resume paused campaign
          inject <campaign_id> <step> - Inject custom step into campaign
          audit <campaign_id>         - Show audit trail for campaign
          help                        - Show this help
          exit / quit                 - Exit shell

        Templates: web_recon, infra_recon, ad_enum, mobile_recon

        Step-by-step mode: Use 'step' to execute one step at a time,
        then inspect findings before continuing with 'resume' or 'step'.
    """)

    prompt = "omni> "

    def __init__(self, config: dict = None, dry_run: bool = False):
        super().__init__()
        self.config = config or {}
        self.dry_run = dry_run

        # Initialize components
        self.store = CampaignStateStore("campaigns")
        self.finding_store = create_finding_store("findings.db")
        self.executor = KaliExecutor(ExecutorConfig())

        # Load scope guard from config
        guard_config = self.config.get("guardrails", {})
        self.scope_guard = ScopeGuard(
            in_scope_hosts=guard_config.get("in_scope_hosts", []),
            forbid=guard_config.get("forbid", []),
            block_out_of_scope=bool(guard_config.get("forbid", [])),
        )
        self.executor.set_scope_guard(self.scope_guard)

        # Tab completion
        self._campaign_cache = []
        self._update_campaign_cache()

    def _update_campaign_cache(self):
        """Update campaign ID cache for tab completion."""
        campaigns = self.store.list()
        self._campaign_cache = [c["id"] for c in campaigns]

    def complete_show(self, text, line, begidx, endidx):
        return [c for c in self._campaign_cache if c.startswith(text)]

    complete_findings = complete_show
    complete_export = complete_show
    complete_step = complete_show
    complete_pause = complete_show
    complete_resume = complete_show
    complete_audit = complete_show

    def complete_run(self, text, line, begidx, endidx):
        parts = shlex.split(line)
        if len(parts) == 2:
            return [t for t in ["web_recon", "infra_recon", "ad_enum", "mobile_recon"] if t.startswith(text)]
        return [c for c in self._campaign_cache if c.startswith(text)]

    complete_plan = complete_run

    def do_run(self, arg: str):
    """run <target> [template] - Create and run a new campaign."""
    args = shlex.split(arg)
    if not args:
        print("Usage: run <target> [template]")
        return

    target = args[0]
    template = args[1] if len(args) > 1 else "web_recon"

    print(f"[+] Creating campaign for {target} using template '{template}'...")
    campaign = self._create_campaign(target, template)

    if self.dry_run:
        print(f"[DRY RUN] Campaign {campaign.id} created (not executed)")
        self._show_campaign_plan(campaign)
        return

    print(f"[+] Campaign {campaign.id} created. Starting execution...")
    self._run_campaign(campaign)

    def do_plan(self, arg: str):
    """plan <target> [template] - Create campaign plan without executing."""
    args = shlex.split(arg)
    if not args:
        print("Usage: plan <target> [template]")
        return

    target = args[0]
    template = args[1] if len(args) > 1 else "web_recon"

    campaign = self._create_campaign(target, template)
    print(f"[+] Campaign {campaign.id} created (planned only)")
    self._show_campaign_plan(campaign)

    def _create_campaign(self, target: str, template: str) -> Campaign:
    from .planner import create_campaign_from_template
    campaign = create_campaign_from_template(template, target)
    self.store.save(campaign)
    return campaign

    def _show_campaign_plan(self, campaign: Campaign):
    print(f"\nCampaign: {campaign.name} ({campaign.id})")
    print(f"Target: {campaign.target}")
    print(f"Template: {campaign.metadata.get('template', 'unknown')}")
    print(f"Steps ({len(campaign.steps)}):")
    for i, step in enumerate(campaign.steps, 1):
        deps = f" (depends on: {', '.join(step.depends_on)})" if step.depends_on else ""
        cond = f" [condition: {step.condition}]" if step.condition else ""
        print(f"  {i}. {step.id} [{step.tool}]{deps}{cond}")
        print(f"     {step.description}")
        print(f"     Args: {' '.join(step.args)}")
    print()
