import asyncio
import os
import pytest
import unittest.mock as mock

from rag.executor import ExecutorConfig, KaliExecutor, SyncKaliExecutor
from rag.models import CampaignStep, ExecutionResult, Finding, Host, Severity, StepState
from rag.scope_guard import ScopeGuard


@pytest.fixture
def dry_executor():
    config = ExecutorConfig(max_concurrent=2, default_timeout=10, dry_run=True)
    return KaliExecutor(config=config)


@pytest.fixture
def scope_guard():
    return ScopeGuard(
        in_scope_hosts=["10.0.0.1", "staging.local", "192.168.1.0/24"],
        forbid=["dos_or_stress_testing", "bulk_real_pii_exfiltration"],
        block_out_of_scope=True,
    )


# ── Configuration & Initialization Tests ─────────────────────────────────────

def test_executor_config_defaults():
    cfg = ExecutorConfig()
    assert cfg.max_concurrent == 3
    assert cfg.default_timeout == 300
    assert cfg.dry_run is False
    assert "PATH" in cfg.env_allowlist
    assert any("AWS_" in p for p in cfg.blocked_env_prefixes)


def test_executor_config_custom():
    cfg = ExecutorConfig(max_concurrent=5, default_timeout=60, dry_run=True)
    assert cfg.max_concurrent == 5
    assert cfg.default_timeout == 60
    assert cfg.dry_run is True


# ── Environment Sanitization Tests ───────────────────────────────────────────

def test_sanitize_env(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIASECRETKEY123")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_tokensecret")
    monkeypatch.setenv("MY_PASSWORD", "supersecret")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("USER", "kali")

    executor = KaliExecutor()
    safe_env = executor._sanitize_env({"CUSTOM_VAR": "safe_value", "SECRET_VAR": "hidden"})

    assert "AWS_SECRET_ACCESS_KEY" not in safe_env
    assert "GITHUB_TOKEN" not in safe_env
    assert "MY_PASSWORD" not in safe_env
    assert "SECRET_VAR" not in safe_env
    assert "CUSTOM_VAR" in safe_env
    assert safe_env["CUSTOM_VAR"] == "safe_value"
    assert safe_env.get("USER") == "kali"


# ── Dry-Run Execution Tests ───────────────────────────────────────────────────

def test_execute_step_dry_run(dry_executor):
    async def _test():
        step = CampaignStep(
            id="recon_nmap",
            tool="nmap",
            args=["-sV", "10.0.0.1"],
            parser="nmap_xml",
            target="10.0.0.1",
        )

        result = await dry_executor.execute_step(step)
        assert isinstance(result, ExecutionResult)
        assert result.step_id == "recon_nmap"
        assert result.success is True
        assert result.return_code == 0
        assert "[dry-run]" in result.raw_output
        assert step.state == StepState.COMPLETED
        assert step.result is not None

    asyncio.run(_test())


# ── ScopeGuard Blocking Tests ─────────────────────────────────────────────────

def test_execute_step_scope_guard_blocked_out_of_scope(dry_executor, scope_guard):
    async def _test():
        dry_executor.set_scope_guard(scope_guard)

        # Out-of-scope target command
        step = CampaignStep(
            id="recon_nmap",
            tool="nmap",
            args=["-sV", "evil.com"],
            target="evil.com",
        )

        result = await dry_executor.execute_step(step)
        assert result.success is False
        assert result.blocked is True
        assert "BLOCKED" in result.block_reason or "out-of-scope" in result.block_reason
        assert step.state == StepState.BLOCKED
        assert step.evidence.get("scope_guard") is not None

    asyncio.run(_test())


def test_execute_step_scope_guard_blocked_forbidden_rule(dry_executor, scope_guard):
    async def _test():
        dry_executor.set_scope_guard(scope_guard)

        # In-scope target but forbidden DoS flag (--flood)
        step = CampaignStep(
            id="recon_flood",
            tool="hping3",
            args=["--flood", "10.0.0.1"],
            target="10.0.0.1",
        )

        result = await dry_executor.execute_step(step)
        assert result.success is False
        assert result.blocked is True
        assert step.state == StepState.BLOCKED

    asyncio.run(_test())


# ── Timeout & Live Execution Handling ─────────────────────────────────────────

def test_execute_step_timeout_handling():
    async def _test():
        executor = KaliExecutor(dry_run=False)

        step = CampaignStep(
            id="slow_step",
            tool="sleep",
            args=["10"],
            timeout=1,
            target="10.0.0.1",
        )

        # Mock subprocess to simulate a timeout
        with mock.patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = mock.AsyncMock()
            mock_proc.communicate.side_effect = asyncio.TimeoutError()
            mock_proc.kill = mock.MagicMock()
            mock_exec.return_value = mock_proc

            result = await executor.execute_step(step)
            assert result.success is False
            assert result.timed_out is True
            assert "timed out" in result.error
            assert step.state == StepState.FAILED

    asyncio.run(_test())


def test_execute_step_empty_arguments():
    async def _test():
        executor = KaliExecutor(dry_run=False)
        step = CampaignStep(id="empty_step", tool="", args=[], command="")

        result = await executor.execute_step(step)
        assert result.success is False
        assert "Empty command" in result.error
        assert step.state == StepState.FAILED

    asyncio.run(_test())


# ── Post-Execution Scope Check Tests ──────────────────────────────────────────

def test_execute_step_post_execution_scope_check(scope_guard):
    async def _test():
        executor = KaliExecutor(dry_run=False)

        step = CampaignStep(
            id="recon_amass",
            tool="amass",
            args=["enum", "-d", "staging.local"],
            parser="amass_json",
            target="staging.local",
        )

        # Discovered output containing both in-scope and out-of-scope subdomains
        stdout_data = (
            '{"name":"app.staging.local","domain":"staging.local","tag":"dns","sources":["DNS"]}\n'
            '{"name":"unauthorized.external.com","domain":"external.com","tag":"dns","sources":["DNS"]}\n'
        ).encode()

        with mock.patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = mock.AsyncMock()
            mock_proc.communicate.return_value = (stdout_data, b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            result = await executor.execute_step(step, scope_guard=scope_guard)
            assert result.success is True
            assert len(result.findings) == 2

            in_scope_finding = next(f for f in result.findings if f.host == "app.staging.local")
            assert in_scope_finding.severity == Severity.INFO

            out_scope_finding = next(f for f in result.findings if f.host == "unauthorized.external.com")
            assert out_scope_finding.severity == Severity.INFO
            assert "out of scope" in out_scope_finding.evidence.get("scope_guard", "")

    asyncio.run(_test())


# ── Synchronous Wrapper Tests ─────────────────────────────────────────────────

def test_sync_kali_executor_dry_run():
    sync_executor = SyncKaliExecutor(dry_run=True)
    assert sync_executor.config.dry_run is True

    step = CampaignStep(
        id="sync_step",
        tool="nmap",
        args=["-sV", "10.0.0.1"],
        parser="nmap_xml",
        target="10.0.0.1",
    )

    result = sync_executor.execute_step(step)
    assert isinstance(result, ExecutionResult)
    assert result.success is True
    assert result.step_id == "sync_step"
    assert step.state == StepState.COMPLETED
