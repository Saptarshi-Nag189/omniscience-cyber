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
import shlex
import sys
import textwrap
try:
    import readline
except ImportError:
    pass
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

    def _run_campaign(self, campaign: Campaign):
        """Execute campaign steps sequentially."""
        self.executor.set_scope_guard(self.scope_guard)

        while True:
            # Get next executable steps
            step_results = {s.id: s.result for s in campaign.steps if s.result}
            next_steps = self._get_executable_steps(campaign, step_results)

            if not next_steps:
                # Check if campaign is complete
                pending = [s for s in campaign.steps if s.state == "pending"]
                if not pending:
                    print("[+] Campaign completed!")
                    self._show_summary(campaign)
                    break
                else:
                    # Check if blocked
                    blocked = [s for s in campaign.steps if s.state == "blocked"]
                    if blocked:
                        print(f"[!] Campaign blocked on {len(blocked)} step(s)")
                        for s in blocked:
                            print(f"    - {s.id}: {s.evidence.get('block_reason', 'unknown')}")
                    else:
                        print("[!] No executable steps but campaign not complete")
                    break

            # Execute next step(s)
            for step_id in next_steps:
                step = next(s for s in campaign.steps if s.id == step_id)
                print(f"\n[>] Executing step: {step_id} ({step.tool})")
                print(f"    Command: {' '.join(step.render_command(build_context(campaign, {s.id: s.result for s in campaign.steps if s.result})))}")

                if self.dry_run:
                    print("    [DRY RUN] Skipping execution")
                    continue

                # Execute step
                async def run_step():
                    return await self.executor.execute_step(step, self.scope_guard)

                result = asyncio.run(run_step())

                # Update campaign
                self._update_step_result(campaign, step_id, result)
                self.store.save(campaign)

                # Show results
                if result.blocked:
                    print(f"    [!] BLOCKED: {result.block_reason}")
                elif result.timed_out:
                    print(f"    [!] TIMEOUT ({result.duration:.1f}s)")
                elif result.success:
                    print(f"    [+] Completed ({result.duration:.1f}s, {len(result.findings)} findings)")
                    for f in result.findings[:3]:
                        print(f"      - {f.title} ({f.severity.value})")
                    if len(result.findings) > 3:
                        print(f"      ... and {len(result.findings) - 3} more")
                else:
                    print(f"    [-] FAILED: {result.errors}")

    def _get_executable_steps(self, campaign: Campaign, step_results: dict) -> List[str]:
        """Get steps that are ready to execute."""
        ready = []
        for step in campaign.steps:
            if step.state != "pending":
                continue

            # Check dependencies
            deps_met = all(step_results.get(dep_id, {}).get("state") == "completed"
                          for dep_id in step.depends_on)
            if not deps_met:
                continue

            # Check condition
            if not self._check_condition(step):
                continue

            ready.append(step.id)
        return ready

    def _check_condition(self, step: CampaignStep) -> bool:
        if not step.condition:
            return True
        # Simple condition evaluation
        # In a full implementation, this would evaluate the condition expression
        return True

    def _update_step_result(self, campaign: Campaign, step_id: str, result):
        for step in campaign.steps:
            if step.id == step_id:
                step.state = "completed" if result.success else "failed"
                step.result = result
                step.completed_at = datetime.utcnow().isoformat()
                break

        # Add findings to campaign
        for finding in result.findings:
            campaign.add_finding(finding)

        campaign.updated_at = datetime.utcnow().isoformat()

    def _show_summary(self, campaign: Campaign):
        stats = self.finding_store.get_stats(campaign.id)
        print(f"\n{'='*60}")
        print(f"CAMPAIGN SUMMARY: {campaign.id}")
        print(f"{'='*60}")
        print(f"Target: {campaign.target}")
        print(f"Total Findings: {stats['total']}")
        for sev, count in stats["by_severity"].items():
            print(f"  {sev.capitalize()}: {count}")
        print(f"\nFindings saved to findings.db")
        print(f"Campaign state saved to campaigns/{campaign.id}.json")

def main():
    parser = argparse.ArgumentParser(description="omniscience-cyber shell")
    parser.add_argument("--dry-run", action="store_true", help="Plan campaigns without executing tools")
    args = parser.parse_args()
    
    shell = OmniscienceShell(dry_run=args.dry_run)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
