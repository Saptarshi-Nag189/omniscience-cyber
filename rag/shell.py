#!/usr/bin/env python3
"""
rag/shell.py — Interactive REPL and CLI management shell for omniscience-cyber.

Features:
  - Interactive commands: target, plan, run, step, status, findings, export,
    audit, ask, tool, harden, list, show, use, pause, resume, help, exit, quit.
  - DAG campaign planning and execution (Nmap, Nuclei, Ffuf, Masscan, Hydra, etc.)
  - Dry-run simulation mode (--dry-run) for testing DAG transitions without Kali binaries.
  - Tamper-evident hash-chain audit logging and verification.
  - Markdown and JSON report generation.
  - Integrated RAG grounding (ask, tool, harden) with local LLMs and ScopeGuard RoE.
  - Cross-platform support (Windows/Linux/macOS) with optional readline and clean EOF handling.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Cross-platform readline support
try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline  # type: ignore
    except ImportError:
        readline = None

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rag.models import (
    Campaign,
    CampaignStep,
    CampaignState,
    ExecutionResult,
    Finding,
    Host,
    Port,
    ScanResult,
    Service,
    Severity,
    StepState,
    utc_now_iso,
    normalize_severity,
)
from rag.state import CampaignStateStore, create_campaign_store
from rag.planner import (
    create_campaign_from_template,
    create_campaign,
    get_next_pending_steps,
    build_context,
    resolve_step_args,
    list_templates,
    get_template,
)
from rag.executor import KaliExecutor, ExecutorConfig
from rag.scope_guard import ScopeGuard
from rag.findings import FindingStore, create_finding_store
from rag.report import ReportGenerator, create_report_generator
from rag.audit import AuditTrail, create_audit_trail
from rag.rag_core import RagCore


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from specified path or default locations."""
    search_paths = []
    if config_path:
        search_paths.append(Path(config_path))
    search_paths.extend([
        Path.cwd() / "config.yaml",
        Path.cwd() / "config.example.yaml",
        REPO_ROOT / "config.yaml",
        REPO_ROOT / "config.example.yaml",
    ])

    for p in search_paths:
        if p.is_file():
            try:
                import yaml
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
    return {}


class OmniscienceShell(cmd.Cmd):
    """Interactive REPL for omniscience-cyber campaigns and cybersecurity RAG."""

    intro = textwrap.dedent("""
        ========================================================================
         OMNISCIENCE-CYBER — Autonomous Penetration Testing & RAG Shell
        ========================================================================
        Commands:
          target <host>               - Set or display current active target
          plan [target] [template]    - Plan campaign DAG without executing
          run [target|id] [template]  - Run or resume a campaign (supports --dry-run)
          step [campaign_id]          - Execute single next step in campaign
          status [campaign_id]        - Display campaign execution state & progress
          findings [id] [severity]    - List findings filtered by severity
          export [id] <filename>      - Export report (Markdown .md or JSON .json)
          audit [campaign_id]         - View audit trail & verify hash chain integrity
          ask <query>                 - Ask security questions to grounded RAG / LLM
          tool <query>                - Generate runnable Kali commands via RAG
          harden <query>              - Get defensive remediation & hardening advice
          list                        - List all stored campaigns
          show <campaign_id>          - Show campaign DAG details
          use <campaign_id>           - Set active campaign
          pause / resume [id]         - Pause or resume campaign execution
          help                        - Show this help
          exit / quit                 - Exit shell
        ========================================================================
    """)

    prompt = "omni> "

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        target: str = "",
    ):
        super().__init__()
        self.config = config or load_config()
        self.dry_run = dry_run
        self.current_target = target.strip()
        self.active_campaign_id: Optional[str] = None

        # Core subsystems
        self.store = create_campaign_store("campaigns")
        self.finding_store = create_finding_store("findings.db")
        self.audit_trail = create_audit_trail("audit.log")
        self.report_gen = create_report_generator(self.finding_store)

        # Scope guard and executor
        self.scope_guard = ScopeGuard.from_config(self.config)
        self.executor = KaliExecutor(ExecutorConfig())
        self.executor.set_scope_guard(self.scope_guard)

        # Lazy initialized RAG core
        self._rag: Optional[RagCore] = None

        # Tab completion cache
        self._campaign_cache: List[str] = []
        self._update_campaign_cache()

    def _get_rag(self) -> RagCore:
        """Lazy loader for RagCore."""
        if self._rag is None:
            self._rag = RagCore(self.config)
        return self._rag

    def _update_campaign_cache(self):
        """Update campaign ID cache for tab completion."""
        try:
            campaigns = self.store.list()
            self._campaign_cache = [c["id"] for c in campaigns if c.get("id")]
        except Exception:
            self._campaign_cache = []

    # ── Tab Completion Helpers ────────────────────────────────────────────────

    def complete_show(self, text, line, begidx, endidx):
        self._update_campaign_cache()
        return [c for c in self._campaign_cache if c.startswith(text)]

    complete_status = complete_show
    complete_findings = complete_show
    complete_export = complete_show
    complete_step = complete_show
    complete_pause = complete_show
    complete_resume = complete_show
    complete_audit = complete_show
    complete_use = complete_show

    def complete_run(self, text, line, begidx, endidx):
        self._update_campaign_cache()
        parts = shlex.split(line[:begidx]) if line[:begidx].strip() else []
        templates = list_templates()
        if len(parts) >= 2:
            return [t for t in templates if t.startswith(text)]
        return [c for c in self._campaign_cache if c.startswith(text)] + [
            t for t in templates if t.startswith(text)
        ]

    def complete_plan(self, text, line, begidx, endidx):
        parts = shlex.split(line[:begidx]) if line[:begidx].strip() else []
        templates = list_templates()
        if len(parts) >= 2:
            return [t for t in templates if t.startswith(text)]
        return [t for t in templates if t.startswith(text)]

    # ── Target Management ─────────────────────────────────────────────────────

    def do_target(self, arg: str):
        """target [host] - Set or display current target host/URL."""
        target = arg.strip()
        if not target:
            if self.current_target:
                print(f"Current target: {self.current_target}")
            else:
                print("No target currently set. Set one with: target <host>")
            return

        self.current_target = target
        print(f"[+] Target set to: {self.current_target}")

    # ── Plan Command ──────────────────────────────────────────────────────────

    def do_plan(self, arg: str):
        """plan [target] [template] - Create campaign DAG plan without executing."""
        args = shlex.split(arg)
        target = ""
        template = "web_recon"

        if len(args) == 0:
            target = self.current_target
        elif len(args) == 1:
            # Check if arg is a template name or target
            available_templates = list_templates()
            if args[0] in available_templates:
                template = args[0]
                target = self.current_target
            else:
                target = args[0]
        elif len(args) >= 2:
            target = args[0]
            template = args[1]

        if not target:
            print("[-] Error: No target specified. Set with 'target <host>' or provide as argument: plan <target> [template]")
            return

        self.current_target = target
        try:
            campaign = create_campaign_from_template(template, target)
        except ValueError as e:
            print(f"[-] Failed to create campaign: {e}")
            templates = list_templates()
            print(f"    Available templates: {', '.join(templates)}")
            return

        self.store.save(campaign)
        self.active_campaign_id = campaign.id
        self._update_campaign_cache()

        self.audit_trail.log(
            event="campaign_planned",
            operator="shell",
            campaign_id=campaign.id,
            command=f"plan {target} {template}",
            verdict="allow",
            extra={"template": template, "steps_count": len(campaign.steps)},
        )

        print(f"[+] Campaign plan created: {campaign.name} ({campaign.id})")
        self._show_campaign_plan(campaign)

    # ── Run Command ───────────────────────────────────────────────────────────

    def do_run(self, arg: str):
        """run [target|campaign_id] [template] - Run or resume a campaign."""
        args = shlex.split(arg)
        target = ""
        template = "web_recon"

        if len(args) == 0:
            if self.active_campaign_id:
                campaign = self.store.load(self.active_campaign_id)
                if campaign:
                    print(f"[*] Resuming active campaign {campaign.id} ({campaign.name})...")
                    self._run_campaign(campaign)
                    return
            target = self.current_target
        elif len(args) == 1:
            arg0 = args[0]
            # Check if arg0 is an existing campaign ID
            existing = self.store.load(arg0)
            if existing:
                self.active_campaign_id = existing.id
                print(f"[*] Resuming existing campaign {existing.id} ({existing.name})...")
                self._run_campaign(existing)
                return

            available_templates = list_templates()
            if arg0 in available_templates and self.current_target:
                template = arg0
                target = self.current_target
            else:
                target = arg0
        elif len(args) >= 2:
            target = args[0]
            template = args[1]

        if not target:
            print("[-] Error: No target specified. Set with 'target <host>' or provide as argument: run <target> [template]")
            return

        self.current_target = target
        try:
            campaign = create_campaign_from_template(template, target)
        except ValueError as e:
            print(f"[-] Failed to create campaign: {e}")
            templates = list_templates()
            print(f"    Available templates: {', '.join(templates)}")
            return

        self.store.save(campaign)
        self.active_campaign_id = campaign.id
        self._update_campaign_cache()

        print(f"[+] Campaign created: {campaign.name} ({campaign.id})")
        self._run_campaign(campaign)

    # ── Step Command ──────────────────────────────────────────────────────────

    def do_step(self, arg: str):
        """step [campaign_id] - Execute single next ready step in campaign."""
        campaign_id = arg.strip() or self.active_campaign_id
        if not campaign_id:
            print("[-] No campaign specified and no active campaign. Usage: step <campaign_id>")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        self.active_campaign_id = campaign.id
        self._execute_campaign_step(campaign)

    # ── Status Command ────────────────────────────────────────────────────────

    def do_status(self, arg: str):
        """status [campaign_id] - Display campaign execution state & step progress."""
        campaign_id = arg.strip() or self.active_campaign_id
        if not campaign_id:
            # Display all campaigns summary
            campaigns = self.store.list()
            if not campaigns:
                print("[-] No campaigns found. Create one with 'plan <target>' or 'run <target>'.")
                return

            print(f"\n{'='*75}")
            print(f"{'ID':<10} {'TARGET':<25} {'STATE':<12} {'FINDINGS':<10} {'UPDATED'}")
            print(f"{'-'*75}")
            for c in campaigns:
                active_mark = "*" if c.get("id") == self.active_campaign_id else " "
                cid = f"{active_mark}{c.get('id', '')}"
                tgt = str(c.get("target", ""))
                st = str(c.get("state", ""))
                fc = c.get("findings_count", 0)
                up = str(c.get("updated_at", ""))[:19]
                print(f"{cid:<10} {tgt[:24]:<25} {st:<12} {fc:<10} {up}")
            print(f"{'='*75}")
            print("(* = currently active campaign)\n")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        state_str = campaign.state.value if isinstance(campaign.state, CampaignState) else str(campaign.state)
        completed_steps = sum(
            1 for s in campaign.steps
            if (s.state.value if isinstance(s.state, StepState) else str(s.state)) == "completed"
        )

        print(f"\n{'='*75}")
        print(f"CAMPAIGN STATUS: {campaign.name} ({campaign.id})")
        print(f"{'='*75}")
        print(f"Target:      {campaign.target}")
        print(f"State:       {state_str.upper()}")
        print(f"Created:     {campaign.created_at}")
        print(f"Updated:     {campaign.updated_at}")
        print(f"Progress:    {completed_steps}/{len(campaign.steps)} steps completed")
        print(f"\nSteps:")
        print(f"{'#':<4} {'STEP ID':<22} {'TOOL':<12} {'STATE':<12} {'FINDINGS'}")
        print(f"{'-'*75}")
        for i, step in enumerate(campaign.steps, 1):
            st = step.state.value if isinstance(step.state, StepState) else str(step.state)
            f_count = 0
            if step.result:
                if hasattr(step.result, "findings"):
                    f_count = len(step.result.findings)
                elif isinstance(step.result, dict):
                    f_count = len(step.result.get("findings", []))
            print(f"{i:<4} {step.id:<22} {step.tool:<12} {st:<12} {f_count}")

        stats = self.finding_store.get_stats(campaign.id)
        print(f"\nFindings Breakdown: {stats.get('total', 0)} total")
        for sev, count in stats.get("by_severity", {}).items():
            print(f"  {sev.capitalize():<12}: {count}")
        print(f"{'='*75}\n")

    # ── Findings Command ──────────────────────────────────────────────────────

    def do_findings(self, arg: str):
        """findings [campaign_id] [severity] - List findings filtered by severity."""
        args = shlex.split(arg)
        campaign_id = None
        severity = None

        valid_severities = {"critical", "high", "medium", "low", "info", "unknown"}

        if len(args) == 1:
            if args[0].lower() in valid_severities:
                severity = args[0].lower()
                campaign_id = self.active_campaign_id
            else:
                campaign_id = args[0]
        elif len(args) >= 2:
            campaign_id = args[0]
            severity = args[1].lower()
        else:
            campaign_id = self.active_campaign_id

        findings = self.finding_store.list(campaign_id=campaign_id, severity=severity)
        if not findings:
            filter_desc = []
            if campaign_id:
                filter_desc.append(f"campaign '{campaign_id}'")
            if severity:
                filter_desc.append(f"severity '{severity}'")
            f_str = " with " + " and ".join(filter_desc) if filter_desc else ""
            print(f"No findings found{f_str}.")
            return

        print(f"\n{'='*80}")
        title_header = f"FINDINGS ({len(findings)})"
        if campaign_id:
            title_header += f" for campaign '{campaign_id}'"
        if severity:
            title_header += f" [{severity.upper()}]"
        print(title_header)
        print(f"{'='*80}")
        print(f"{'ID':<10} {'SEVERITY':<10} {'TOOL':<10} {'TARGET':<25} {'TITLE'}")
        print(f"{'-'*80}")
        for f in findings:
            sev_val = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            tgt = f.host or f.target or "-"
            if f.port:
                tgt = f"{tgt}:{f.port}"
            print(f"{f.id:<10} {sev_val.upper():<10} {f.tool:<10} {tgt[:24]:<25} {f.title}")
        print(f"{'='*80}\n")

    # ── Export Command ────────────────────────────────────────────────────────

    def do_export(self, arg: str):
        """export [campaign_id] <filename> - Export Markdown or JSON report."""
        if not arg or not arg.strip():
            args = []
        else:
            try:
                args = shlex.split(arg.strip(), posix=(os.name != "nt"))
            except Exception:
                args = arg.strip().split()

        campaign_id = None
        dest = None

        if len(args) == 0:
            campaign_id = self.active_campaign_id
            dest = f"report_{campaign_id}.md" if campaign_id else "report.md"
        elif len(args) == 1:
            arg0 = args[0]
            if (
                arg0.endswith(".md")
                or arg0.endswith(".json")
                or arg0.endswith(".html")
                or arg0.lower() in ("md", "json", "markdown")
                or "\\" in arg0
                or "/" in arg0
            ):
                campaign_id = self.active_campaign_id
                dest = arg0
            else:
                campaign_id = arg0
                dest = f"report_{campaign_id}.md"
        else:
            campaign_id = args[0]
            dest = args[1]

        if not campaign_id:
            print("[-] No campaign specified and no active campaign. Usage: export [campaign_id] <filename>")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        is_json = dest.endswith(".json") or dest.lower() == "json"
        if is_json:
            report_content = self.report_gen.export_findings_json(campaign_id)
            out_path = dest if dest.endswith(".json") else f"report_{campaign_id}.json"
        else:
            report_content = self.report_gen.generate_markdown(campaign_id)
            out_path = dest if dest.endswith(".md") else f"report_{campaign_id}.md"

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            print(f"[+] Report exported successfully to: {out_path}")
            self.audit_trail.log(
                event="report_exported",
                operator="shell",
                campaign_id=campaign_id,
                command=f"export {out_path}",
                verdict="allow",
                extra={"filename": out_path, "format": "json" if is_json else "markdown"},
            )
        except Exception as e:
            print(f"[-] Failed to write report to {out_path}: {e}")

    # ── Audit Command ─────────────────────────────────────────────────────────

    def do_audit(self, arg: str):
        """audit [campaign_id] - View tamper-evident audit trail & verify chain integrity."""
        campaign_id = arg.strip() or None

        # Verify hash chain integrity
        verification = self.audit_trail.verify_chain()
        print(f"\n{'='*80}")
        print(f"AUDIT TRAIL INTEGRITY VERIFICATION")
        print(f"{'='*80}")
        if verification.get("valid"):
            print(f"Integrity Status: [OK] VALID (Checked {verification.get('entries_checked', 0)} entries, 0 errors)")
        else:
            print(f"Integrity Status: [!] BROKEN / TAMPERED ({len(verification.get('errors', []))} errors found)")
            for err in verification.get("errors", []):
                print(f"  Line {err.get('line')}: {err.get('error')}")

        # Query entries
        entries = self.audit_trail.query(campaign_id=campaign_id, limit=50)
        print(f"\nRecent Audit Entries ({len(entries)}):")
        print(f"{'-'*80}")
        print(f"{'TIMESTAMP':<22} {'OPERATOR':<10} {'CAMPAIGN':<10} {'EVENT':<18} {'VERDICT':<8} {'HASH'}")
        print(f"{'-'*80}")
        for entry in entries:
            ts = str(entry.get("timestamp", ""))[:19]
            op = str(entry.get("operator", "shell"))[:10]
            cid = str(entry.get("campaign_id", "-"))[:10]
            ev = str(entry.get("event", ""))[:18]
            vd = str(entry.get("verdict", "-"))[:8]
            h = str(entry.get("hash", ""))[:12]
            print(f"{ts:<22} {op:<10} {cid:<10} {ev:<18} {vd:<8} {h}")
        print(f"{'='*80}\n")

    # ── RAG / LLM Commands ────────────────────────────────────────────────────

    def do_ask(self, arg: str):
        """ask <query> - Ask grounded cybersecurity questions to RAG / LLM."""
        query = arg.strip()
        if not query:
            print("Usage: ask <security question>")
            return

        try:
            rag = self._get_rag()
            print(f"[*] Querying RAG for: '{query}'...")
            res = rag.ask(query)
            print(f"\n{res.get('answer', '')}\n")
            if res.get("cards"):
                print(f"[Cards cited] {', '.join(res['cards'])}")
            if res.get("model"):
                print(f"[Model used]  {res['model']}")
        except Exception as e:
            print(f"[-] RAG query failed: {e}")

    def do_tool(self, arg: str):
        """tool <task> - Generate runnable Kali commands via RAG."""
        task = arg.strip()
        if not task:
            print("Usage: tool <recon/exploit task description>")
            return

        try:
            rag = self._get_rag()
            print(f"[*] Generating tool commands for: '{task}'...")
            res = rag.tool(task)
            print("\nGenerated Command(s):")
            for cmd_line in res.get("commands", []):
                print(f"  {cmd_line}")
            if res.get("blocked"):
                print(f"\n[!] Scope Guard blocked/flagged {len(res['blocked'])} command(s):")
                for b in res["blocked"]:
                    print(f"    - {b.get('command')}: {', '.join(b.get('reasons', []))}")
        except Exception as e:
            print(f"[-] Tool generation failed: {e}")

    def do_harden(self, arg: str):
        """harden <query> - Produce defensive remediation & hardening guidance."""
        subject = arg.strip()
        if not subject:
            print("Usage: harden <finding / asset / misconfiguration description>")
            return

        try:
            rag = self._get_rag()
            print(f"[*] Generating hardening guidance for: '{subject}'...")
            res = rag.harden(subject)
            print(f"\n{res.get('answer', '')}\n")
            if res.get("cards"):
                print(f"[Cards cited] {', '.join(res['cards'])}")
            if res.get("model"):
                print(f"[Model used]  {res['model']}")
        except Exception as e:
            print(f"[-] Hardening guidance query failed: {e}")

    # ── Campaign Management Commands ──────────────────────────────────────────

    def do_list(self, arg: str):
        """list - List all stored campaigns."""
        campaigns = self.store.list()
        if not campaigns:
            print("No campaigns found.")
            return

        print(f"\n{'='*75}")
        print(f"{'ID':<10} {'TARGET':<25} {'NAME':<20} {'STATE':<10} {'FINDINGS'}")
        print(f"{'-'*75}")
        for c in campaigns:
            active_mark = "*" if c.get("id") == self.active_campaign_id else " "
            cid = f"{active_mark}{c.get('id', '')}"
            tgt = str(c.get("target", ""))
            name = str(c.get("name", ""))[:19]
            st = str(c.get("state", ""))
            fc = c.get("findings_count", 0)
            print(f"{cid:<10} {tgt[:24]:<25} {name:<20} {st:<10} {fc}")
        print(f"{'='*75}")
        print("(* = currently active campaign)\n")

    def do_show(self, arg: str):
        """show [campaign_id] - Show detailed information of a campaign."""
        campaign_id = arg.strip() or self.active_campaign_id
        if not campaign_id:
            print("[-] No campaign specified and no active campaign. Usage: show <campaign_id>")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        self._show_campaign_plan(campaign)

    def do_use(self, arg: str):
        """use <campaign_id> - Set the active campaign."""
        campaign_id = arg.strip()
        if not campaign_id:
            print("Usage: use <campaign_id>")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        self.active_campaign_id = campaign.id
        self.current_target = campaign.target
        print(f"[+] Active campaign set to: {campaign.id} ({campaign.name}) [Target: {campaign.target}]")

    def do_pause(self, arg: str):
        """pause [campaign_id] - Pause a running campaign."""
        campaign_id = arg.strip() or self.active_campaign_id
        if not campaign_id:
            print("[-] No campaign specified. Usage: pause <campaign_id>")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        campaign.state = CampaignState.PAUSED
        self.store.save(campaign)
        print(f"[+] Campaign {campaign.id} paused.")

    def do_resume(self, arg: str):
        """resume [campaign_id] - Resume execution of a paused campaign."""
        campaign_id = arg.strip() or self.active_campaign_id
        if not campaign_id:
            print("[-] No campaign specified. Usage: resume <campaign_id>")
            return

        campaign = self.store.load(campaign_id)
        if not campaign:
            print(f"[-] Campaign '{campaign_id}' not found.")
            return

        self.active_campaign_id = campaign.id
        print(f"[+] Resuming campaign {campaign.id}...")
        self._run_campaign(campaign)

    # ── Shell Exit & Lifecycle ────────────────────────────────────────────────

    def do_exit(self, arg: str):
        """exit - Exit the shell."""
        print("Exiting omniscience shell. Goodbye.")
        return True

    def do_quit(self, arg: str):
        """quit - Exit the shell."""
        return self.do_exit(arg)

    def do_EOF(self, arg: str):
        """Handle EOF (Ctrl+D) cleanly without looping."""
        print()
        return self.do_exit(arg)

    def emptyline(self):
        """Do nothing on empty line."""
        pass

    # ── Execution Logic ───────────────────────────────────────────────────────

    def _show_campaign_plan(self, campaign: Campaign):
        """Display planned DAG steps and configuration."""
        print(f"\nCampaign:    {campaign.name} ({campaign.id})")
        print(f"Target:      {campaign.target or '(none)'}")
        state_str = campaign.state.value if isinstance(campaign.state, CampaignState) else str(campaign.state)
        print(f"State:       {state_str.upper()}")
        template_name = (
            campaign.metadata.get("template", "custom")
            if isinstance(campaign.metadata, dict)
            else "custom"
        )
        print(f"Template:    {template_name}")
        print(f"Steps ({len(campaign.steps)}):")

        step_results = {s.id: s.result for s in campaign.steps if s.result is not None}
        context = build_context(campaign, step_results)

        for i, step in enumerate(campaign.steps, 1):
            deps = f" (depends on: {', '.join(step.depends_on)})" if step.depends_on else ""
            cond = f" [condition: {step.condition}]" if step.condition else ""
            st = step.state.value if isinstance(step.state, StepState) else str(step.state)
            print(f"  {i}. {step.id} [{step.tool}] [{st.upper()}]{deps}{cond}")
            if step.description:
                print(f"     Description: {step.description}")
            cmd_args = resolve_step_args(step, context)
            print(f"     Command:     {' '.join(cmd_args)}")
        print()

    def _run_campaign(self, campaign: Campaign):
        """Execute campaign steps sequentially until complete or blocked."""
        campaign.state = CampaignState.RUNNING
        self.store.save(campaign)
        self.active_campaign_id = campaign.id

        print(f"\n[*] Starting campaign execution for {campaign.name} ({campaign.id})")
        mode_label = "DRY RUN (Simulation)" if self.dry_run else "LIVE (Executing tools)"
        print(f"    Target: {campaign.target} | Mode: {mode_label}")

        while True:
            step_results = {s.id: s.result for s in campaign.steps if s.result is not None}
            next_steps = get_next_pending_steps(campaign, step_results)

            if not next_steps:
                pending = [
                    s for s in campaign.steps
                    if (s.state.value if isinstance(s.state, StepState) else str(s.state)) == "pending"
                ]
                if not pending:
                    campaign.state = CampaignState.COMPLETED
                    campaign.completed_at = utc_now_iso()
                    campaign.updated_at = utc_now_iso()
                    self.store.save(campaign)
                    print("\n[+] All campaign steps completed successfully!")
                    self._show_summary(campaign)
                    break
                else:
                    blocked = [
                        s for s in campaign.steps
                        if (s.state.value if isinstance(s.state, StepState) else str(s.state)) == "blocked"
                    ]
                    if blocked:
                        campaign.state = CampaignState.FAILED
                        self.store.save(campaign)
                        print(f"\n[!] Campaign blocked on {len(blocked)} step(s):")
                        for s in blocked:
                            reason = (
                                s.evidence.get("block_reason", "unknown")
                                if isinstance(s.evidence, dict)
                                else "unknown"
                            )
                            print(f"    - {s.id}: {reason}")
                    else:
                        print("\n[!] No further executable steps ready (unmet dependencies or conditions).")
                    break

            # Execute ready steps
            for step_id in next_steps:
                step = next((s for s in campaign.steps if s.id == step_id), None)
                if not step:
                    continue

                context = build_context(
                    campaign,
                    {s.id: s.result for s in campaign.steps if s.result is not None},
                )
                argv = resolve_step_args(step, context)
                cmd_str = " ".join(argv)

                print(f"\n[>] Executing step: {step.id} ({step.tool})")
                print(f"    Command: {cmd_str}")

                if self.dry_run:
                    result = self._simulate_step_execution(step, campaign, context)
                else:
                    async def _exec():
                        return await self.executor.execute_step(step, self.scope_guard)
                    result = asyncio.run(_exec())

                self._update_step_result(campaign, step.id, result)
                self.store.save(campaign)

                # Audit trail logging
                verdict = "dry_run" if self.dry_run else ("block" if result.blocked else "allow")
                self.audit_trail.log(
                    event="step_execution",
                    operator="shell",
                    campaign_id=campaign.id,
                    step_id=step.id,
                    command=cmd_str,
                    verdict=verdict,
                    findings_count=len(result.findings),
                    duration=result.duration,
                    extra={"dry_run": self.dry_run, "success": result.success},
                )

                # Display result summary
                if result.blocked:
                    print(f"    [!] BLOCKED by Scope Guard: {result.block_reason}")
                elif result.timed_out:
                    print(f"    [!] TIMEOUT ({result.duration:.1f}s)")
                elif result.success:
                    mode_tag = " [DRY RUN]" if self.dry_run else ""
                    print(f"    [+] Completed{mode_tag} ({result.duration:.1f}s, {len(result.findings)} finding(s))")
                    for f in result.findings[:5]:
                        sev_val = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
                        print(f"      - [{sev_val.upper()}] {f.title}")
                    if len(result.findings) > 5:
                        print(f"      ... and {len(result.findings) - 5} more")
                else:
                    err_msg = ", ".join(result.errors) if result.errors else (result.error or "Unknown error")
                    print(f"    [-] FAILED: {err_msg}")

    def _execute_campaign_step(self, campaign: Campaign):
        """Execute a single next ready step in the campaign."""
        step_results = {s.id: s.result for s in campaign.steps if s.result is not None}
        next_steps = get_next_pending_steps(campaign, step_results)

        if not next_steps:
            pending = [
                s for s in campaign.steps
                if (s.state.value if isinstance(s.state, StepState) else str(s.state)) == "pending"
            ]
            if not pending:
                print("[+] All steps in campaign are already completed!")
                campaign.state = CampaignState.COMPLETED
                self.store.save(campaign)
            else:
                print("[!] No steps currently ready to execute.")
            return

        step_id = next_steps[0]
        step = next(s for s in campaign.steps if s.id == step_id)

        context = build_context(campaign, step_results)
        argv = resolve_step_args(step, context)
        cmd_str = " ".join(argv)

        print(f"\n[>] Executing single step: {step.id} ({step.tool})")
        print(f"    Command: {cmd_str}")

        if self.dry_run:
            result = self._simulate_step_execution(step, campaign, context)
        else:
            async def _exec():
                return await self.executor.execute_step(step, self.scope_guard)
            result = asyncio.run(_exec())

        self._update_step_result(campaign, step.id, result)
        self.store.save(campaign)

        verdict = "dry_run" if self.dry_run else ("block" if result.blocked else "allow")
        self.audit_trail.log(
            event="step_execution",
            operator="shell",
            campaign_id=campaign.id,
            step_id=step.id,
            command=cmd_str,
            verdict=verdict,
            findings_count=len(result.findings),
            duration=result.duration,
            extra={"dry_run": self.dry_run, "success": result.success},
        )

        if result.success:
            mode_tag = " [DRY RUN]" if self.dry_run else ""
            print(f"    [+] Step completed{mode_tag} ({result.duration:.1f}s, {len(result.findings)} finding(s))")
        else:
            print(f"    [-] Step execution failed.")

    def _simulate_step_execution(
        self,
        step: CampaignStep,
        campaign: Campaign,
        context: Dict[str, Any],
    ) -> ExecutionResult:
        """Simulate tool execution for dry-run mode without live Kali binaries."""
        argv = resolve_step_args(step, context)
        cmd_str = " ".join(argv)
        tool = (step.tool or "generic").lower()
        target = campaign.target or "127.0.0.1"

        hosts: List[Host] = []
        findings: List[Finding] = []

        if "nmap" in tool:
            # Simulate open ports: 80 (http), 443 (https), 22 (ssh)
            ports = [
                Port(
                    number=80,
                    protocol="tcp",
                    state="open",
                    service=Service(name="http", product="nginx", version="1.24.0"),
                ),
                Port(
                    number=443,
                    protocol="tcp",
                    state="open",
                    service=Service(name="https", product="nginx", version="1.24.0"),
                ),
                Port(
                    number=22,
                    protocol="tcp",
                    state="open",
                    service=Service(name="ssh", product="OpenSSH", version="8.9p1"),
                ),
            ]
            host = Host(address=target, hostnames=[target], ports=ports, status="up")
            hosts.append(host)
            findings.append(Finding(
                tool="nmap",
                vuln_type="service_discovery",
                title=f"Open Port 80/tcp (http: nginx 1.24.0)",
                host=target,
                port=80,
                severity=Severity.INFO,
                description="Nginx HTTP service discovered",
                evidence={"service": "http", "port": 80, "product": "nginx"},
                tags=["nmap", "port", "discovery"],
            ))
            findings.append(Finding(
                tool="nmap",
                vuln_type="service_discovery",
                title=f"Open Port 443/tcp (https: nginx 1.24.0)",
                host=target,
                port=443,
                severity=Severity.INFO,
                description="Nginx HTTPS service discovered",
                evidence={"service": "https", "port": 443, "product": "nginx"},
                tags=["nmap", "port", "discovery"],
            ))
            findings.append(Finding(
                tool="nmap",
                vuln_type="service_discovery",
                title=f"Open Port 22/tcp (ssh: OpenSSH 8.9p1)",
                host=target,
                port=22,
                severity=Severity.INFO,
                description="OpenSSH service discovered",
                evidence={"service": "ssh", "port": 22, "product": "OpenSSH"},
                tags=["nmap", "port", "discovery"],
            ))
        elif "nuclei" in tool:
            findings.append(Finding(
                tool="nuclei",
                vuln_type="cve_vulnerability",
                title=f"CVE-2021-44228: Apache Log4j JNDI RCE (Simulated)",
                description="Remote code execution vulnerability via JNDI injection (dry-run simulation)",
                host=target,
                port=443,
                target=f"https://{target}:443",
                parameter="X-Api-Version",
                severity=Severity.HIGH,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cve_ids=["CVE-2021-44228"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                tags=["cve", "rce", "nuclei", "simulated"],
                evidence={"template_id": "CVE-2021-44228", "matched_at": f"https://{target}:443"},
            ))
            findings.append(Finding(
                tool="nuclei",
                vuln_type="security_misconfiguration",
                title=f"Missing Strict-Transport-Security Header (Simulated)",
                description="HSTS security header is missing on the HTTPS endpoint",
                host=target,
                port=443,
                target=f"https://{target}:443",
                severity=Severity.LOW,
                cvss_score=3.1,
                tags=["misconfig", "headers", "nuclei", "simulated"],
                evidence={"template_id": "hsts-missing", "matched_at": f"https://{target}:443"},
            ))
        elif "ffuf" in tool:
            findings.append(Finding(
                tool="ffuf",
                vuln_type="directory_discovery",
                title=f"Discovered path: http://{target}/admin",
                description="Discovered admin portal endpoint (HTTP 200, 1420 bytes)",
                host=target,
                port=80,
                target=f"http://{target}/admin",
                parameter="/admin",
                severity=Severity.LOW,
                evidence={"url": f"http://{target}/admin", "status": 200, "length": 1420},
                tags=["ffuf", "discovery", "admin", "simulated"],
            ))
            findings.append(Finding(
                tool="ffuf",
                vuln_type="directory_discovery",
                title=f"Discovered path: http://{target}/api/v1/health",
                description="Discovered API health endpoint (HTTP 200, 58 bytes)",
                host=target,
                port=80,
                target=f"http://{target}/api/v1/health",
                parameter="/api/v1/health",
                severity=Severity.INFO,
                evidence={"url": f"http://{target}/api/v1/health", "status": 200, "length": 58},
                tags=["ffuf", "discovery", "api", "simulated"],
            ))
        elif "sqlmap" in tool:
            findings.append(Finding(
                tool="sqlmap",
                vuln_type="sql_injection",
                title=f"SQL Injection in parameter id (Simulated)",
                description="Boolean-based blind SQL injection in parameter 'id'",
                host=target,
                port=80,
                target=f"http://{target}/items?id=1",
                parameter="id",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                tags=["sqlmap", "sqli", "critical", "simulated"],
                evidence={"parameter": "id", "dbms": "PostgreSQL"},
            ))
        elif "hydra" in tool:
            findings.append(Finding(
                tool="hydra",
                vuln_type="credential_brute_force",
                title=f"Valid credentials found: admin:admin123 (Simulated)",
                description="Brute-force succeeded for SSH service",
                host=target,
                port=22,
                target=f"{target}:22",
                parameter="ssh://admin",
                severity=Severity.HIGH,
                cvss_score=8.8,
                tags=["hydra", "credentials", "ssh", "simulated"],
                evidence={"login": "admin", "service": "ssh"},
            ))
        elif "masscan" in tool:
            ports = [
                Port(number=80, protocol="tcp", state="open"),
                Port(number=443, protocol="tcp", state="open"),
                Port(number=22, protocol="tcp", state="open"),
            ]
            hosts.append(Host(address=target, ports=ports, status="up"))

        return ExecutionResult(
            step_id=step.id,
            tool=step.tool,
            target=target,
            command=cmd_str,
            success=True,
            duration=0.1,
            duration_seconds=0.1,
            findings=findings,
            hosts=hosts,
            raw_output=f"[DRY RUN SIMULATION] Step {step.id} executed successfully.",
        )

    def _update_step_result(self, campaign: Campaign, step_id: str, result: ExecutionResult):
        """Update step state and persist findings."""
        for step in campaign.steps:
            if step.id == step_id:
                step.state = StepState.COMPLETED if result.success else StepState.FAILED
                step.result = result
                step.completed_at = utc_now_iso()
                break

        for finding in result.findings:
            campaign.add_finding(finding)
            self.finding_store.add(finding)

        campaign.updated_at = utc_now_iso()

    def _show_summary(self, campaign: Campaign):
        """Display campaign summary stats."""
        stats = self.finding_store.get_stats(campaign.id)
        print(f"\n{'='*60}")
        print(f"CAMPAIGN SUMMARY: {campaign.name} ({campaign.id})")
        print(f"{'='*60}")
        print(f"Target:         {campaign.target}")
        state_str = campaign.state.value if isinstance(campaign.state, CampaignState) else str(campaign.state)
        print(f"Status:         {state_str.upper()}")
        print(f"Total Findings: {stats.get('total', 0)}")
        for sev, count in stats.get("by_severity", {}).items():
            print(f"  {sev.capitalize():<12}: {count}")
        print(f"\nCampaign state saved to campaigns/{campaign.id}.json")
        print(f"Findings persisted to findings.db")
        print(f"{'='*60}\n")


def main():
    """Main CLI entrypoint for omniscience-cyber shell."""
    parser = argparse.ArgumentParser(
        description="omniscience-cyber interactive REPL & campaign manager"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run campaign DAG in simulation mode without executing live Kali tools",
    )
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        default="",
        help="Default target host or URL",
    )
    parser.add_argument(
        "--template",
        type=str,
        default="web_recon",
        help="Default campaign template (default: web_recon)",
    )
    parser.add_argument(
        "--run",
        type=str,
        default="",
        help="Non-interactively run a campaign for the specified target and exit",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="",
        help="Path to YAML configuration file",
    )
    args = parser.parse_args()

    cfg = load_config(args.config) if args.config else load_config()
    shell = OmniscienceShell(config=cfg, dry_run=args.dry_run, target=args.target)

    if args.run:
        # Non-interactive CLI run mode
        target = args.run.strip()
        template = args.template
        print(f"[*] Non-interactive run on target: {target} [template: {template}]")
        campaign = create_campaign_from_template(template, target)
        shell.store.save(campaign)
        shell._run_campaign(campaign)
        return

    try:
        shell.cmdloop()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting omniscience shell. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
