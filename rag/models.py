from __future__ import annotations

"""
rag/models.py — Core data models, enums, and dataclasses for omniscience-cyber.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union


# ── Enums ─────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class CampaignState(str, Enum):
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class Verdict(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class ToolName(str, Enum):
    NMAP = "nmap"
    NUCLEI = "nuclei"
    FFUF = "ffuf"
    SQLMAP = "sqlmap"
    HYDRA = "hydra"
    MASSCAN = "masscan"
    AMASS = "amass"
    GENERIC = "generic"


# ── Helper Functions ──────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_severity(severity: Union[str, Severity]) -> Severity:
    """Normalize arbitrary severity strings to standard Severity enum."""
    if isinstance(severity, Severity):
        return severity
    if not isinstance(severity, str):
        return Severity.UNKNOWN
    s = severity.lower().strip()
    mapping = {
        "critical": Severity.CRITICAL,
        "crit": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "none": Severity.INFO,
        "neg": Severity.INFO,
        "neglectable": Severity.INFO,
        "unknown": Severity.UNKNOWN,
    }
    return mapping.get(s, Severity.UNKNOWN)


# ── Network & Recon Data Models ───────────────────────────────────────────────

@dataclass
class Service:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    ostype: str = ""
    method: str = ""
    conf: int = 0
    cpe: List[str] = field(default_factory=list)
    scripts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Service:
        data = data.copy()
        scripts = data.get("scripts", [])
        if isinstance(scripts, dict):
            data["scripts"] = [{"id": str(k), "output": str(v)} for k, v in scripts.items()]
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class Port:
    number: int = 0
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[Service] = None
    scripts: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    reason_ttl: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        number: Optional[int] = None,
        port: Optional[int] = None,
        protocol: str = "tcp",
        state: str = "open",
        service: Optional[Union[Service, Dict[str, Any]]] = None,
        scripts: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None,
        reason: str = "",
        reason_ttl: int = 0,
        extra: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        if number is not None:
            self.number = int(number)
        elif port is not None:
            self.number = int(port)
        else:
            self.number = 0
        self.protocol = protocol
        self.state = state
        if isinstance(service, dict):
            self.service = Service.from_dict(service)
        else:
            self.service = service

        if scripts is None:
            self.scripts = []
        elif isinstance(scripts, dict):
            self.scripts = [{"id": str(k), "output": str(v)} for k, v in scripts.items()]
        elif isinstance(scripts, list):
            self.scripts = list(scripts)
        else:
            self.scripts = []

        self.reason = reason
        self.reason_ttl = reason_ttl
        self.extra = extra or {}
        if kwargs:
            self.extra.update(kwargs)

    @property
    def port(self) -> int:
        return self.number

    @port.setter
    def port(self, value: int) -> None:
        self.number = int(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "number": self.number,
            "port": self.number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service.to_dict() if self.service else None,
            "scripts": self.scripts,
            "reason": self.reason,
            "reason_ttl": self.reason_ttl,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Port:
        data = data.copy()
        service_data = data.pop("service", None)
        service = Service.from_dict(service_data) if isinstance(service_data, dict) else service_data
        num = data.pop("number", None)
        p = data.pop("port", None)
        num_val = num if num is not None else p
        return cls(number=num_val, service=service, **data)


@dataclass
class Host:
    address: str = ""
    hostnames: List[str] = field(default_factory=list)
    ports: List[Port] = field(default_factory=list)
    os: Optional[Union[Dict[str, Any], str]] = None
    uptime: Optional[str] = None
    distance: Optional[int] = None
    status: str = "up"
    reason: str = ""
    os_matches: List[Dict[str, Any]] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def open_ports(self) -> List[Port]:
        return [p for p in self.ports if p.state == "open"]

    def get_open_ports(self) -> List[Port]:
        return self.open_ports()

    def web_ports(self) -> List[Port]:
        web_port_numbers = {80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 4000, 5000}
        return [p for p in self.open_ports() if p.number in web_port_numbers]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ports"] = [p.to_dict() if hasattr(p, "to_dict") else p for p in self.ports]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Host:
        data = data.copy()
        ports_data = data.pop("ports", [])
        ports = [Port.from_dict(p) if isinstance(p, dict) else p for p in ports_data]
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(ports=ports, **filtered)


# ── Findings & Vulnerabilities ────────────────────────────────────────────────

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    campaign_id: str = ""
    step_id: str = ""
    tool: str = ""
    vuln_type: str = ""
    title: str = ""
    description: str = ""
    host: str = ""
    port: Optional[int] = None
    parameter: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: Severity = Severity.UNKNOWN
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    status: str = "open"
    dedup_hash: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    target: str = ""
    raw_output: str = ""

    def __post_init__(self):
        if not self.target and self.host:
            self.target = f"{self.host}:{self.port}" if self.port else self.host
        elif self.target and not self.host:
            self.host = self.target
        if not self.dedup_hash:
            self.compute_dedup_hash()

    def compute_dedup_hash(self) -> str:
        if not self.vuln_type and not self.title:
            key = f"{self.id}|{self.host}|{self.tool}"
        else:
            key = f"{self.vuln_type}|{self.host}|{self.port or ''}|{self.parameter}|{self.title}"
        self.dedup_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return self.dedup_hash

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        d["tool"] = self.tool.value if isinstance(self.tool, ToolName) else str(self.tool)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        data = data.copy()
        sev = data.get("severity", "unknown")
        data["severity"] = normalize_severity(sev)

        tool_val = data.get("tool", "")
        if isinstance(tool_val, ToolName):
            data["tool"] = tool_val.value
        else:
            data["tool"] = str(tool_val)

        if isinstance(data.get("evidence"), str):
            try:
                data["evidence"] = json.loads(data["evidence"])
            except Exception:
                data["evidence"] = {"raw": data["evidence"]}

        if isinstance(data.get("cve_ids"), str):
            try:
                data["cve_ids"] = json.loads(data["cve_ids"])
            except Exception:
                data["cve_ids"] = [data["cve_ids"]] if data["cve_ids"] else []

        if isinstance(data.get("references"), str):
            try:
                data["references"] = json.loads(data["references"])
            except Exception:
                data["references"] = [data["references"]] if data["references"] else []

        if isinstance(data.get("tags"), str):
            try:
                data["tags"] = json.loads(data["tags"])
            except Exception:
                data["tags"] = [data["tags"]] if data["tags"] else []

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class Vulnerability(Finding):
    finding: Optional[Finding] = None
    cve_id: str = ""
    cwe_id: str = ""
    exploit_available: bool = False
    exploit_code: str = ""
    exploit_references: List[str] = field(default_factory=list)
    patch_available: bool = False
    remediation: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        if self.finding:
            d["finding"] = self.finding.to_dict() if hasattr(self.finding, "to_dict") else self.finding
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Vulnerability:
        data = data.copy()
        finding_data = data.pop("finding", None)
        finding_obj = None
        if isinstance(finding_data, dict):
            finding_obj = Finding.from_dict(finding_data)
        elif isinstance(finding_data, Finding):
            finding_obj = finding_data

        sev = data.get("severity", "unknown")
        data["severity"] = normalize_severity(sev)

        tool_val = data.get("tool", "")
        if isinstance(tool_val, ToolName):
            data["tool"] = tool_val.value
        else:
            data["tool"] = str(tool_val)

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        vuln = cls(finding=finding_obj, **filtered)
        return vuln


def create_finding(
    tool: Union[ToolName, str],
    title: str,
    target: str = "",
    severity: Union[str, Severity] = Severity.UNKNOWN,
    description: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    references: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    raw_output: str = "",
    host: str = "",
    port: Optional[int] = None,
    vuln_type: str = "",
    parameter: str = "",
    cvss_score: float = 0.0,
    cvss_vector: str = "",
    cve_ids: Optional[List[str]] = None,
) -> Finding:
    sev = normalize_severity(severity)
    tool_str = tool.value if isinstance(tool, ToolName) else str(tool)
    f_host = host or target
    return Finding(
        tool=tool_str,
        title=title,
        description=description,
        severity=sev,
        target=target,
        host=f_host,
        port=port,
        vuln_type=vuln_type or title,
        parameter=parameter,
        evidence=evidence or {},
        references=references or [],
        tags=tags or [],
        raw_output=raw_output,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cve_ids=cve_ids or [],
    )


# ── Execution Results & Tracking ──────────────────────────────────────────────

@dataclass
class ScanResult:
    tool: str = ""
    target: str = ""
    command: str = ""
    raw_output: str = ""
    parsed_hosts: List[Host] = field(default_factory=list)
    parsed_findings: List[Finding] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=utc_now_iso)
    started_at: str = ""
    completed_at: str = ""
    success: bool = True
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    hosts: List[Host] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def __post_init__(self):
        if self.parsed_hosts and not self.hosts:
            self.hosts = self.parsed_hosts
        elif self.hosts and not self.parsed_hosts:
            self.parsed_hosts = self.hosts

        if self.parsed_findings and not self.findings:
            self.findings = self.parsed_findings
        elif self.findings and not self.parsed_findings:
            self.parsed_findings = self.findings

        if self.duration and not self.duration_seconds:
            self.duration_seconds = self.duration
        elif self.duration_seconds and not self.duration:
            self.duration = self.duration_seconds

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding not in self.parsed_findings:
            self.parsed_findings.append(finding)

    def add_host(self, host: Host) -> None:
        self.hosts.append(host)
        if host not in self.parsed_hosts:
            self.parsed_hosts.append(host)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tool"] = self.tool.value if isinstance(self.tool, ToolName) else str(self.tool)
        d["parsed_hosts"] = [h.to_dict() if hasattr(h, "to_dict") else h for h in self.parsed_hosts]
        d["hosts"] = [h.to_dict() if hasattr(h, "to_dict") else h for h in self.hosts]
        d["parsed_findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.parsed_findings]
        d["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]
        d["vulnerabilities"] = [v.to_dict() if hasattr(v, "to_dict") else v for v in self.vulnerabilities]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanResult:
        data = data.copy()
        raw_hosts = data.pop("parsed_hosts", None) or data.pop("hosts", [])
        hosts = [Host.from_dict(h) if isinstance(h, dict) else h for h in raw_hosts]

        raw_findings = data.pop("parsed_findings", None) or data.pop("findings", [])
        findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in raw_findings]

        vulns_data = data.pop("vulnerabilities", [])
        vulns = [Vulnerability.from_dict(v) if isinstance(v, dict) else v for v in vulns_data]

        tool_val = data.get("tool", "")
        if isinstance(tool_val, ToolName):
            data["tool"] = tool_val.value
        else:
            data["tool"] = str(tool_val)

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        filtered.pop("hosts", None)
        filtered.pop("parsed_hosts", None)
        filtered.pop("findings", None)
        filtered.pop("parsed_findings", None)
        filtered.pop("vulnerabilities", None)
        return cls(
            parsed_hosts=hosts,
            hosts=hosts,
            parsed_findings=findings,
            findings=findings,
            vulnerabilities=vulns,
            **filtered,
        )


@dataclass
class CampaignStep:
    id: str
    tool: str = ""
    args: List[str] = field(default_factory=list)
    command: str = ""
    parser: str = ""
    description: str = ""
    depends_on: List[str] = field(default_factory=list)
    condition: str = ""
    timeout: int = 300
    env: Dict[str, str] = field(default_factory=dict)
    working_dir: str = ""
    state: StepState = StepState.PENDING
    result: Optional[Union[ScanResult, ExecutionResult, Dict[str, Any]]] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    target: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def render_command(self, context: Optional[Dict[str, Any]] = None) -> List[str]:
        ctx = context or {}
        rendered = []
        if self.args:
            for arg in self.args:
                arg_str = str(arg)
                for key, value in ctx.items():
                    if isinstance(value, list):
                        arg_str = arg_str.replace(f"{{{{{key}}}}}", " ".join(str(v) for v in value))
                    else:
                        arg_str = arg_str.replace(f"{{{{{key}}}}}", str(value))
                rendered.append(arg_str)
            # Ensure tool binary is the first argument if not already included
            if self.tool and self.tool not in ("generic", ""):
                if not rendered or (rendered[0] != self.tool and not rendered[0].endswith("/" + self.tool)):
                    rendered = [self.tool] + rendered
            return rendered
        elif self.command:
            cmd = self.command
            for key, value in ctx.items():
                if isinstance(value, list):
                    cmd = cmd.replace(f"{{{{{key}}}}}", " ".join(str(v) for v in value))
                else:
                    cmd = cmd.replace(f"{{{{{key}}}}}", str(value))
            import shlex
            return shlex.split(cmd)
        elif self.tool:
            return [self.tool]
        return []

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value if isinstance(self.state, StepState) else str(self.state)
        d["tool"] = self.tool.value if isinstance(self.tool, ToolName) else str(self.tool)
        if self.result:
            if hasattr(self.result, "to_dict"):
                d["result"] = self.result.to_dict()
            elif isinstance(self.result, dict):
                d["result"] = self.result
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CampaignStep:
        data = data.copy()
        state_val = data.get("state", "pending")
        if isinstance(state_val, str):
            try:
                data["state"] = StepState(state_val)
            except ValueError:
                data["state"] = StepState.PENDING
        elif isinstance(state_val, StepState):
            data["state"] = state_val

        result_data = data.get("result")
        if isinstance(result_data, dict):
            if "parsed_hosts" in result_data or "parsed_findings" in result_data:
                data["result"] = ScanResult.from_dict(result_data)
            elif "success" in result_data and "step_id" in result_data:
                data["result"] = ExecutionResult.from_dict(result_data)
            else:
                data["result"] = result_data

        tool_val = data.get("tool", "")
        if isinstance(tool_val, ToolName):
            data["tool"] = tool_val.value
        else:
            data["tool"] = str(tool_val)

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        extra = {k: v for k, v in data.items() if k not in valid_fields}
        if extra:
            meta = filtered.get("metadata", {})
            meta.update(extra)
            filtered["metadata"] = meta
        return cls(**filtered)


@dataclass
class ExecutionResult:
    step_id: str
    tool: str = ""
    target: str = ""
    command: str = ""
    success: bool = False
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)
    raw_output: str = ""
    stderr: str = ""
    return_code: int = -1
    blocked: bool = False
    block_reason: str = ""
    timed_out: bool = False
    scope_decision: Optional[Dict[str, Any]] = None
    error: str = ""
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.duration and not self.duration_seconds:
            self.duration_seconds = self.duration
        elif self.duration_seconds and not self.duration:
            self.duration = self.duration_seconds

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tool"] = self.tool.value if isinstance(self.tool, ToolName) else str(self.tool)
        d["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]
        d["hosts"] = [h.to_dict() if hasattr(h, "to_dict") else h for h in self.hosts]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionResult:
        data = data.copy()
        findings_data = data.pop("findings", [])
        findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]
        hosts_data = data.pop("hosts", [])
        hosts = [Host.from_dict(h) if isinstance(h, dict) else h for h in hosts_data]

        tool_val = data.get("tool", "")
        if isinstance(tool_val, ToolName):
            data["tool"] = tool_val.value
        else:
            data["tool"] = str(tool_val)

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(findings=findings, hosts=hosts, **filtered)


# ── Audit Logging ─────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    timestamp: str = field(default_factory=utc_now_iso)
    step_id: str = ""
    tool: str = ""
    target: str = ""
    command: str = ""
    verdict: str = ""
    scope_reasons: List[str] = field(default_factory=list)
    execution_time_ms: int = 0
    duration: float = 0.0
    findings_count: int = 0
    blocked: bool = False
    timed_out: bool = False
    return_code: int = -1
    error: str = ""
    operator: str = ""
    event: str = ""
    campaign_id: str = ""
    prev_hash: str = ""
    hash: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditEntry:
        data = data.copy()
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        extra = {k: v for k, v in data.items() if k not in valid_fields}
        if extra:
            extra_dict = filtered.get("extra", {})
            extra_dict.update(extra)
            filtered["extra"] = extra_dict
        return cls(**filtered)

    @classmethod
    def from_json_line(cls, line: str) -> AuditEntry:
        return cls.from_dict(json.loads(line))


# ── Campaign Container ────────────────────────────────────────────────────────

@dataclass
class Campaign:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    name: str = ""
    description: str = ""
    steps: List[CampaignStep] = field(default_factory=list)
    state: CampaignState = CampaignState.PLANNING
    findings: List[Finding] = field(default_factory=list)
    scope_guard_config: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    completed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        finding.campaign_id = self.id
        finding.compute_dedup_hash()
        for existing in self.findings:
            if existing.dedup_hash == finding.dedup_hash:
                existing.evidence.update(finding.evidence)
                existing.updated_at = utc_now_iso()
                return
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Union[Severity, str]) -> List[Finding]:
        sev = normalize_severity(severity)
        return [f for f in self.findings if f.severity == sev]

    def critical_high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value if isinstance(self.state, CampaignState) else str(self.state)
        d["steps"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps]
        d["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]
        d["scope_guard_config"] = self.scope_guard_config
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Campaign:
        data = data.copy()
        state_val = data.get("state", "planning")
        if isinstance(state_val, str):
            try:
                data["state"] = CampaignState(state_val)
            except ValueError:
                data["state"] = CampaignState.PLANNING
        elif isinstance(state_val, CampaignState):
            data["state"] = state_val

        steps_data = data.get("steps", [])
        data["steps"] = [CampaignStep.from_dict(s) if isinstance(s, dict) else s for s in steps_data]

        findings_data = data.get("findings", [])
        data["findings"] = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        extra = {k: v for k, v in data.items() if k not in valid_fields}
        if extra:
            meta = filtered.get("metadata", {})
            meta.update(extra)
            filtered["metadata"] = meta
        return cls(**filtered)


# ── Serialization Helpers ─────────────────────────────────────────────────────

def to_json(obj: Any) -> str:
    """Serialize any model or dict to JSON string."""
    if hasattr(obj, "to_dict"):
        return json.dumps(obj.to_dict(), indent=2, default=str)
    return json.dumps(obj, indent=2, default=str)


def from_json(json_str: str, cls: type) -> Any:
    """Deserialize JSON string to model class instance."""
    data = json.loads(json_str)
    if hasattr(cls, "from_dict"):
        return cls.from_dict(data)
    return cls(**data)
