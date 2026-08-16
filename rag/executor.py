from __future__ import annotations

import asyncio
import logging
import time
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from .models import CampaignStep, ExecutionResult, Finding, Host, Severity
from .parsers import parse_scan_result
from .scope_guard import ScopeGuard

logger = logging.getLogger(__name__)


@dataclass
class ExecutorConfig:
    max_concurrent: int = 3
    default_timeout: int = 300
    env_allowlist: List[str] = field(default_factory=lambda: [
        'PATH', 'HOME', 'USER', 'LANG', 'LC_ALL',
        'TERM', 'SHELL', 'PWD', 'OLDPWD'
    ])
    blocked_env_prefixes: List[str] = field(default_factory=lambda: [
        'AWS_', 'AZURE_', 'GCP_', 'DOCKER_', 'KUBE_',
        'TOKEN', 'SECRET', 'KEY', 'PASS', 'CRED'
    ])


class KaliExecutor:
    def __init__(self, config: Optional[ExecutorConfig] = None):
        self.config = config or ExecutorConfig()
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._scope_guard: Optional[ScopeGuard] = None
    
    def set_scope_guard(self, scope_guard: ScopeGuard):
        self._scope_guard = scope_guard
    
    def _sanitize_env(self, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        safe_env = {}
        for key, value in os.environ.items():
            if any(key.startswith(prefix) for prefix in self.config.blocked_env_prefixes):
                continue
            if key in self.config.env_allowlist or not any(key.startswith(p) for p in self.config.blocked_env_prefixes):
                safe_env[key] = value
        if extra_env:
            safe_env.update(extra_env)
        return safe_env
    
    async def execute_step(self, step: CampaignStep, scope_guard: Optional[ScopeGuard] = None) -> ExecutionResult:
        start_time = time.time()
        
        # Pre-execution scope check
        guard = scope_guard or self._scope_guard
        if guard:
            rendered_cmd = ' '.join(step.render_command({}))
            decision = guard.check_command(rendered_cmd)
            if decision.verdict == 'block':
                return ExecutionResult(
                    step_id=step.id,
                    success=False,
                    blocked=True,
                    block_reason=decision.annotation(),
                    duration=time.time() - start_time,
                )
        
        async with self.semaphore:
            try:
                step.state = 'running'
                step.started_at = time.time()
                
                argv = step.render_command({})
                if not argv:
                    return ExecutionResult(
                        step_id=step.id,
                        success=False,
                        errors=['Empty command'],
                        duration=time.time() - start_time,
                    )
                
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=self._sanitize_env(step.env),
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=step.timeout
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    return ExecutionResult(
                        step_id=step.id,
                        success=False,
                        timed_out=True,
                        stderr=stderr.decode() if stderr else '',
                        duration=time.time() - start_time,
                    )
                
                stdout_text = stdout.decode() if stdout else ''
                stderr_text = stderr.decode() if stderr else ''
                
                # Parse output
                scan_result = parse_scan_result(
                    step.parser, stdout_text, step.tool, '', ' '.join(argv)
                )
                scan_result.duration = time.time() - start_time
                
                # Post-execution scope re-check on discovered targets
                if guard:
                    for finding in scan_result.parsed_findings:
                        if finding.host and not guard.is_in_scope(finding.host):
                            finding.severity = Severity.INFO
                            finding.evidence['scope_guard'] = f'Discovered target {finding.host} out of scope'
                    for host in scan_result.parsed_hosts:
                        if host.address and not guard.is_in_scope(host.address):
                            host.extra['scope_guard'] = f'Discovered target {host.address} out of scope'
                
                step.result = scan_result
                step.state = 'completed'
                step.completed_at = time.time()
                
                return ExecutionResult(
                    step_id=step.id,
                    success=proc.returncode == 0,
                    findings=scan_result.parsed_findings,
                    hosts=scan_result.parsed_hosts,
                    raw_output=stdout_text,
                    stderr=stderr_text,
                    duration=time.time() - start_time,
                    errors=scan_result.errors if scan_result.errors else None,
                )
                
            except Exception as e:
                logger.exception('Step execution failed')
                step.state = 'failed'
                return ExecutionResult(
                    step_id=step.id,
                    success=False,
                    errors=[str(e)],
                    duration=time.time() - start_time,
                )


# Synchronous wrapper for backward compatibility
class SyncKaliExecutor:
    def __init__(self, config: Optional[ExecutorConfig] = None):
        self.async_executor = KaliExecutor(config)
    
    def set_scope_guard(self, scope_guard: ScopeGuard):
        self.async_executor.set_scope_guard(scope_guard)
    
    def execute_step(self, step: CampaignStep, scope_guard: Optional[ScopeGuard] = None) -> ExecutionResult:
        return asyncio.run(self.async_executor.execute_step(step, scope_guard))
