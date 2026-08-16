from __future__ import annotations

"""
rag/executor.py — Kali Linux command execution engine with concurrency limits,
sandboxed environments, timeout enforcement, dry-run simulation, and ScopeGuard enforcement.
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import CampaignStep, ExecutionResult, Finding, Host, Severity, StepState, utc_now_iso
from .parsers import parse_scan_result
from .scope_guard import ScopeGuard

logger = logging.getLogger(__name__)


@dataclass
class ExecutorConfig:
    max_concurrent: int = 3
    default_timeout: int = 300
    dry_run: bool = False
    env_allowlist: List[str] = field(
        default_factory=lambda: [
            "PATH", "HOME", "USER", "LANG", "LC_ALL",
            "TERM", "SHELL", "PWD", "OLDPWD",
            "SYSTEMROOT", "COMSPEC", "PATHEXT", "TMP", "TEMP",
        ]
    )
    blocked_env_prefixes: List[str] = field(
        default_factory=lambda: [
            "AWS_", "AZURE_", "GCP_", "GOOGLE_", "DOCKER_", "KUBE_",
            "TOKEN", "SECRET", "KEY", "PASS", "PASSWORD", "CRED",
            "AUTH", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "SESSION",
        ]
    )


class KaliExecutor:
    """
    Asynchronous executor for Kali security tools and CLI tasks.
    Enforces concurrency limits, sanitizes credentials from the environment,
    kills hung child processes on timeout, and integrates pre/post ScopeGuard policies.
    """

    def __init__(self, config: Optional[ExecutorConfig] = None, dry_run: bool = False):
        self.config = config or ExecutorConfig(dry_run=dry_run)
        if dry_run:
            self.config.dry_run = True
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._scope_guard: Optional[ScopeGuard] = None

    def set_scope_guard(self, scope_guard: ScopeGuard) -> None:
        """Set the active default ScopeGuard for pre- and post-execution checks."""
        self._scope_guard = scope_guard

    def _sanitize_env(self, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Sanitize environment variables by stripping cloud credentials, tokens,
        and secrets, retaining only safe system variables and explicit overrides.
        """
        safe_env: Dict[str, str] = {}
        blocked_prefixes_upper = [p.upper() for p in self.config.blocked_env_prefixes]
        allowlist_upper = {k.upper() for k in self.config.env_allowlist}

        for key, value in os.environ.items():
            key_upper = key.upper()
            if any(key_upper.startswith(prefix) for prefix in blocked_prefixes_upper):
                continue
            if key_upper in allowlist_upper:
                safe_env[key] = value

        if extra_env:
            for k, v in extra_env.items():
                k_upper = k.upper()
                if not any(k_upper.startswith(prefix) for prefix in blocked_prefixes_upper):
                    safe_env[k] = str(v)

        return safe_env

    async def execute_step(
        self,
        step: CampaignStep,
        scope_guard: Optional[ScopeGuard] = None,
        dry_run: Optional[bool] = None,
    ) -> ExecutionResult:
        """
        Execute a single campaign step with full safety lifecycle:
        1. Render command arguments.
        2. Evaluate pre-execution ScopeGuard constraints.
        3. Acquire concurrency semaphore.
        4. In dry-run mode: return simulated success output.
        5. In live mode: spawn subprocess with sanitized env & enforce timeout.
        6. Parse output and apply post-execution discovered target filtering.
        """
        start_time = time.time()
        started_iso = utc_now_iso()
        argv = step.render_command({})
        cmd_str = step.command if step.command else (" ".join(argv) if argv else step.tool)

        # Determine effective dry_run mode
        effective_dry_run = self.config.dry_run if dry_run is None else dry_run
        if step.metadata and step.metadata.get("dry_run"):
            effective_dry_run = True

        # Pre-execution scope check
        guard = scope_guard or self._scope_guard
        if guard:
            decision = guard.check_command(cmd_str)
            if not decision.allowed or decision.verdict == "block":
                duration = time.time() - start_time
                step.state = StepState.BLOCKED
                step.completed_at = utc_now_iso()
                step.evidence["scope_guard"] = decision.annotation()
                return ExecutionResult(
                    step_id=step.id,
                    tool=step.tool,
                    target=step.target,
                    command=cmd_str,
                    success=False,
                    blocked=True,
                    block_reason=decision.annotation(),
                    scope_decision=decision.to_dict() if hasattr(decision, "to_dict") else None,
                    duration=duration,
                    duration_seconds=duration,
                    started_at=started_iso,
                    completed_at=step.completed_at,
                )

        async with self.semaphore:
            # Handle Dry-Run Mode
            if effective_dry_run:
                duration = time.time() - start_time
                step.state = StepState.COMPLETED
                step.started_at = started_iso
                step.completed_at = utc_now_iso()
                simulated_output = (
                    f"[dry-run] Simulated successful execution for tool='{step.tool}': {cmd_str}"
                )
                scan_result = parse_scan_result(
                    step.parser, simulated_output, step.tool, step.target, cmd_str
                )
                scan_result.duration = duration
                scan_result.duration_seconds = duration
                step.result = scan_result

                return ExecutionResult(
                    step_id=step.id,
                    tool=step.tool,
                    target=step.target,
                    command=cmd_str,
                    success=True,
                    findings=scan_result.parsed_findings,
                    hosts=scan_result.parsed_hosts,
                    raw_output=simulated_output,
                    stderr="",
                    return_code=0,
                    duration=duration,
                    duration_seconds=duration,
                    started_at=started_iso,
                    completed_at=step.completed_at,
                )

            # Live Subprocess Execution
            if not argv:
                duration = time.time() - start_time
                step.state = StepState.FAILED
                step.completed_at = utc_now_iso()
                return ExecutionResult(
                    step_id=step.id,
                    tool=step.tool,
                    target=step.target,
                    command=cmd_str,
                    success=False,
                    error="Empty command arguments",
                    errors=["Empty command arguments"],
                    duration=duration,
                    duration_seconds=duration,
                    started_at=started_iso,
                    completed_at=step.completed_at,
                )

            step.state = StepState.RUNNING
            step.started_at = started_iso
            timeout_limit = step.timeout if (step.timeout and step.timeout > 0) else self.config.default_timeout

            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=self._sanitize_env(step.env),
                    cwd=step.working_dir or None,
                )

                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout_limit,
                    )
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except (ProcessLookupError, OSError):
                        pass
                    try:
                        stdout_bytes, stderr_bytes = await proc.communicate()
                    except Exception:
                        stdout_bytes, stderr_bytes = b"", b""

                    duration = time.time() - start_time
                    step.state = StepState.FAILED
                    step.completed_at = utc_now_iso()
                    return ExecutionResult(
                        step_id=step.id,
                        tool=step.tool,
                        target=step.target,
                        command=cmd_str,
                        success=False,
                        timed_out=True,
                        error=f"Step timed out after {timeout_limit} seconds",
                        errors=[f"Step timed out after {timeout_limit} seconds"],
                        stderr=stderr_bytes.decode(errors="replace") if stderr_bytes else "",
                        duration=duration,
                        duration_seconds=duration,
                        started_at=started_iso,
                        completed_at=step.completed_at,
                    )

                stdout_text = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
                stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
                duration = time.time() - start_time

                # Parse scan output
                scan_result = parse_scan_result(
                    step.parser, stdout_text, step.tool, step.target, cmd_str
                )
                scan_result.duration = duration
                scan_result.duration_seconds = duration

                # Post-execution scope check on discovered hosts/findings
                if guard:
                    for finding in scan_result.parsed_findings:
                        if finding.host and not guard.is_in_scope(finding.host):
                            finding.severity = Severity.INFO
                            finding.evidence["scope_guard"] = f"Discovered target {finding.host} out of scope"
                    for host in scan_result.parsed_hosts:
                        if host.address and not guard.is_in_scope(host.address):
                            host.extra["scope_guard"] = f"Discovered target {host.address} out of scope"

                step.result = scan_result
                step.state = StepState.COMPLETED if proc.returncode == 0 else StepState.FAILED
                step.completed_at = utc_now_iso()

                return ExecutionResult(
                    step_id=step.id,
                    tool=step.tool,
                    target=step.target,
                    command=cmd_str,
                    success=(proc.returncode == 0),
                    return_code=proc.returncode if proc.returncode is not None else -1,
                    findings=scan_result.parsed_findings,
                    hosts=scan_result.parsed_hosts,
                    raw_output=stdout_text,
                    stderr=stderr_text,
                    duration=duration,
                    duration_seconds=duration,
                    started_at=started_iso,
                    completed_at=step.completed_at,
                    errors=scan_result.errors if scan_result.errors else [],
                )

            except Exception as e:
                logger.exception("Step %s execution failed: %s", step.id, e)
                duration = time.time() - start_time
                step.state = StepState.FAILED
                step.completed_at = utc_now_iso()
                return ExecutionResult(
                    step_id=step.id,
                    tool=step.tool,
                    target=step.target,
                    command=cmd_str,
                    success=False,
                    error=str(e),
                    errors=[str(e)],
                    duration=duration,
                    duration_seconds=duration,
                    started_at=started_iso,
                    completed_at=step.completed_at,
                )


class SyncKaliExecutor:
    """Synchronous wrapper for KaliExecutor."""

    def __init__(self, config: Optional[ExecutorConfig] = None, dry_run: bool = False):
        self.async_executor = KaliExecutor(config=config, dry_run=dry_run)

    @property
    def config(self) -> ExecutorConfig:
        return self.async_executor.config

    def set_scope_guard(self, scope_guard: ScopeGuard) -> None:
        self.async_executor.set_scope_guard(scope_guard)

    def execute_step(
        self,
        step: CampaignStep,
        scope_guard: Optional[ScopeGuard] = None,
        dry_run: Optional[bool] = None,
    ) -> ExecutionResult:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import nest_asyncio
                nest_asyncio.apply()
                return loop.run_until_complete(
                    self.async_executor.execute_step(step, scope_guard, dry_run=dry_run)
                )
            else:
                return loop.run_until_complete(
                    self.async_executor.execute_step(step, scope_guard, dry_run=dry_run)
                )
        except RuntimeError:
            return asyncio.run(
                self.async_executor.execute_step(step, scope_guard, dry_run=dry_run)
            )
