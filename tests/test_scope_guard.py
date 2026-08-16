import pytest

from rag.scope_guard import Decision, ScopeGuard


@pytest.fixture
def standard_guard():
    return ScopeGuard(
        in_scope_hosts=["staging.example.com", "10.10.0.0/24", "*.corp.local", "192.168.1.50"],
        forbid=[
            "dos_or_stress_testing",
            "bulk_real_pii_exfiltration",
            "out_of_scope_targets",
            "destructive_commands",
        ],
        block_out_of_scope=True,
    )


# ── Target Extraction Tests ───────────────────────────────────────────────────

def test_extract_targets_urls_and_hosts(standard_guard):
    cmd1 = "curl https://api.staging.example.com/users -H 'Auth: Bearer 123'"
    targets1 = standard_guard.extract_targets(cmd1)
    assert "api.staging.example.com" in targets1

    cmd2 = "nmap -sV -p 8080 192.168.1.50:8080"
    targets2 = standard_guard.extract_targets(cmd2)
    assert "192.168.1.50" in targets2


def test_extract_targets_filters_placeholders_and_files(standard_guard):
    cmd = "ffuf -w /usr/share/wordlists/common.txt -u https://staging.example.com/FUZZ -c config.yaml"
    targets = standard_guard.extract_targets(cmd)
    assert "staging.example.com" in targets
    assert "common.txt" not in targets
    assert "config.yaml" not in targets
    assert "localhost" not in targets
    assert "127.0.0.1" not in targets
    assert "<target>" not in targets


# ── In-Scope Matching Tests ───────────────────────────────────────────────────

def test_in_scope_domain_and_subdomains(standard_guard):
    assert standard_guard.in_scope("staging.example.com") is True
    assert standard_guard.in_scope("api.staging.example.com") is True
    assert standard_guard.in_scope("prod.example.com") is False
    assert standard_guard.in_scope("otherdomain.com") is False


def test_in_scope_wildcard(standard_guard):
    assert standard_guard.in_scope("sub.corp.local") is True
    assert standard_guard.in_scope("deep.nested.sub.corp.local") is True
    assert standard_guard.in_scope("corp.local") is True
    assert standard_guard.in_scope("corp.com") is False


def test_in_scope_cidr_and_ip(standard_guard):
    assert standard_guard.in_scope("10.10.0.1") is True
    assert standard_guard.in_scope("10.10.0.254") is True
    assert standard_guard.in_scope("10.10.1.1") is False
    assert standard_guard.in_scope("192.168.1.50") is True
    assert standard_guard.in_scope("192.168.1.51") is False


def test_in_scope_with_ports(standard_guard):
    assert standard_guard.in_scope("staging.example.com:443") is True
    assert standard_guard.in_scope("10.10.0.5:8080") is True
    assert standard_guard.in_scope("evil.com:80") is False


def test_empty_scope_permits_all():
    guard = ScopeGuard(in_scope_hosts=[], block_out_of_scope=False)
    assert guard.in_scope("anything.com") is True
    assert guard.in_scope("1.2.3.4") is True


# ── Dangerous Rule Blocking Tests ─────────────────────────────────────────────

def test_block_dos_and_stress(standard_guard):
    assert standard_guard.check_command("hping3 --flood 10.10.0.5").verdict == "block"
    assert standard_guard.check_command("slowloris staging.example.com").verdict == "block"
    assert standard_guard.check_command("nmap -T5 10.10.0.5").verdict == "block"
    assert standard_guard.check_command("nmap --min-rate 50000 10.10.0.5").verdict == "block"
    assert standard_guard.check_command("masscan -p80 --rate 60000 10.10.0.5").verdict == "block"
    assert standard_guard.check_command("ffuf -rate 0 -u https://staging.example.com/FUZZ").verdict == "block"


def test_block_bulk_pii_and_os_breakout(standard_guard):
    assert standard_guard.check_command("sqlmap -u 'https://staging.example.com/x?id=1' --dump-all").verdict == "block"
    assert standard_guard.check_command("sqlmap -u 'https://staging.example.com/x?id=1' --os-shell").verdict == "block"
    assert standard_guard.check_command("sqlmap -u 'https://staging.example.com/x?id=1' --os-cmd whoami").verdict == "block"


def test_block_unthrottled_brute_force(standard_guard):
    # Hydra without -t limit
    assert standard_guard.check_command("hydra -l admin -P rockyou.txt staging.example.com ssh").verdict == "block"
    # Hydra with excessive concurrency (-t 100)
    assert standard_guard.check_command("hydra -l admin -P rockyou.txt -t 100 staging.example.com ssh").verdict == "block"
    # Medusa without -t limit
    assert standard_guard.check_command("medusa -h 10.10.0.5 -u admin -P pass.txt -M ssh").verdict == "block"


def test_block_destructive_commands(standard_guard):
    assert standard_guard.check_command("rm -rf /").verdict == "block"
    assert standard_guard.check_command("mkfs.ext4 /dev/sda1").verdict == "block"
    assert standard_guard.check_command("dd if=/dev/zero of=/dev/sda").verdict == "block"


# ── Allowed Safe Commands Tests ───────────────────────────────────────────────

def test_allow_safe_commands(standard_guard):
    safe_commands = [
        "nmap -sV -T2 10.10.0.5",
        "nuclei -u https://staging.example.com -rl 20 -tags cve",
        "ffuf -w wordlist.txt -u https://api.staging.example.com/FUZZ -rate 50",
        "sqlmap -u 'https://staging.example.com/x?id=1' --dump -C name --start 1 --stop 1",
        "hydra -l admin -P rockyou.txt -t 4 staging.example.com ssh",
        "curl https://sub.corp.local/health",
        "# This is a comment",
    ]
    for cmd in safe_commands:
        decision = standard_guard.check_command(cmd)
        assert decision.verdict == "allow", f"Expected allow for '{cmd}', got '{decision.verdict}' ({decision.reasons})"
        assert decision.allowed is True


# ── Out-of-Scope Warning vs Blocking ──────────────────────────────────────────

def test_out_of_scope_blocking(standard_guard):
    d = standard_guard.check_command("nmap -sV 8.8.8.8")
    assert d.verdict == "block"
    assert d.allowed is False
    assert "8.8.8.8" in d.out_of_scope


def test_out_of_scope_warning_when_not_blocking():
    guard = ScopeGuard(
        in_scope_hosts=["staging.example.com"],
        forbid=[],
        block_out_of_scope=False,
    )
    d = guard.check_command("curl https://unlisted-target.com")
    assert d.verdict == "warn"
    assert d.allowed is True
    assert "unlisted-target.com" in d.out_of_scope


# ── Filter Commands and from_config Tests ─────────────────────────────────────

def test_filter_commands(standard_guard):
    commands = [
        "nmap -sV 10.10.0.5",
        "nmap -sV --flood 10.10.0.5",
        "curl https://evil.com/api",
    ]
    safe, decisions = standard_guard.filter_commands(commands)
    assert len(safe) == 3
    assert len(decisions) == 3

    assert safe[0] == "nmap -sV 10.10.0.5"
    assert safe[1].startswith("# BLOCKED:")
    assert safe[2].startswith("# BLOCKED:")


def test_scope_guard_from_config():
    cfg = {
        "guardrails": {
            "in_scope_hosts": ["10.0.0.1", "test.local"],
            "forbid": ["dos_or_stress_testing"],
            "block_out_of_scope": True,
        }
    }
    guard = ScopeGuard.from_config(cfg)
    assert "10.0.0.1" in guard.in_scope_hosts
    assert "test.local" in guard.in_scope_hosts
    assert "dos_or_stress_testing" in guard.forbid
    assert guard.block_out_of_scope is True
