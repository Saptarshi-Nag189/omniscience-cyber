from __future__ import annotations
"""
Data models for omniscience-cyber execution engine.
"""
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json

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

@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional["Service"] = None
    scripts: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.service:
            d["service"] = self.service.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Port":
        service = data.get("service")
        if service:
            data = data.copy()
            data["service"] = Service.from_dict(service)
        return cls(**data)

@dataclass
class Service:
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: List[str] = field(default_factory=list)
    scripts: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Service":
        return cls(**data)

@dataclass
class Host:
    address: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[Port] = field(default_factory=list)
    os: Optional[Dict[str, Any]] = None
    uptime: Optional[str] = None
    distance: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def open_ports(self) -> List[Port]:
        return [p for p in self.ports if p.state == "open"]

    def web_ports(self) -> List[Port]:
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 4000, 5000}
        return [p for p in self.open_ports() if p.number in web_ports]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ports"] = [p.to_dict() for p in self.ports]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Host":
        data = data.copy()
        data["ports"] = [Port.from_dict(p) for p in data.get("ports", [])]
        return cls(**data)
#!/usr/bin/env python3
"""
rag/models.py — Dataclasses for structured scan results and execution tracking.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


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


@dataclass
class Service:
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    ostype: str = ""
    method: str = ""
    conf: int = 0
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Service:
        return cls(**data)


@dataclass
class Port:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    reason: str = ""
    reason_ttl: int = 0
    service: Optional[Service] = None
    scripts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.service:
            d["service"] = self.service.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Port:
        service_data = data.pop("service", None)
        port = cls(**data)
        if service_data:
            port.service = Service.from_dict(service_data)
        return port


@dataclass
class Host:
    address: str
    hostnames: list[str] = field(default_factory=list)
    status: str = "up"
    reason: str = ""
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ports"] = [p.to_dict() for p in self.ports]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Host:
        ports_data = data.pop("ports", [])
        host = cls(**data)
        host.ports = [Port.from_dict(p) for p in ports_data]
        return host

    def get_open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]
# ── Findings & Vulnerabilities ────────────────────────────────────────────────

@dataclass
class Finding:
    tool: ToolName
    title: str
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    target: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool"] = self.tool.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        data = data.copy()
        data["tool"] = ToolName(data.get("tool", "generic"))
        data["severity"] = Severity(data.get("severity", "unknown"))
        return cls(**data)


@dataclass
class Vulnerability(Finding):
    cve_id: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    exploit_available: bool = False
    patch_available: bool = False
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Vulnerability:
        data = data.copy()
        data["tool"] = ToolName(data.get("tool", "generic"))
        data["severity"] = Severity(data.get("severity", "unknown"))
        return cls(**data)


@dataclass
class ScanResult:
    tool: ToolName
    target: str
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_output: str = ""
    command: str = ""
    success: bool = True
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool"] = self.tool.value
        d["hosts"] = [h.to_dict() for h in self.hosts]
        d["findings"] = [f.to_dict() for f in self.findings]
        d["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        data = data.copy()
        data["tool"] = ToolName(data.get("tool", "generic"))
        data["hosts"] = [Host.from_dict(h) for h in data.get("hosts", [])]
        data["findings"] = [Finding.from_dict(f) for f in data.get("findings", [])]
        data["vulnerabilities"] = [Vulnerability.from_dict(v) for v in data.get("vulnerabilities", [])]
        return cls(**data)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_host(self, host: Host) -> None:
        self.hosts.append(host)
# ── Execution Tracking ────────────────────────────────────────────────────────

@dataclass
class CampaignStep:
    id: str
    tool: ToolName
    command: str
    target: str
    parser: str = ""
    timeout: int = 300
    env: dict[str, str] = field(default_factory=dict)
    working_dir: str = ""
    depends_on: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool"] = self.tool.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CampaignStep:
        data = data.copy()
        data["tool"] = ToolName(data.get("tool", "generic"))
        return cls(**data)


@dataclass
class ExecutionResult:
    step_id: str
    tool: ToolName
    target: str
    command: str
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    stderr: str = ""
    return_code: int = -1
    blocked: bool = False
    timed_out: bool = False
    scope_decision: Optional[dict[str, Any]] = None
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool"] = self.tool.value
        d["findings"] = [f.to_dict() for f in self.findings]
        if self.scope_decision:
            d["scope_decision"] = self.scope_decision
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionResult:
        data = data.copy()
        data["tool"] = ToolName(data.get("tool", "generic"))
        data["findings"] = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(**data)

    @property
    def success(self) -> bool:
        return not self.blocked and not self.timed_out and self.return_code == 0


# ── Audit Logging ─────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    step_id: str = ""
    tool: str = ""
    target: str = ""
    command: str = ""
    verdict: str = ""
    scope_reasons: list[str] = field(default_factory=list)
    execution_time_ms: int = 0
    findings_count: int = 0
    blocked: bool = False
    timed_out: bool = False
    return_code: int = -1
    error: str = ""
    operator: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        return cls(**data)

    @classmethod
    def from_json_line(cls, line: str) -> AuditEntry:
        return cls.from_dict(json.loads(line))


# ── Utility Functions ─────────────────────────────────────────────────────────

def normalize_severity(severity: str) -> Severity:
    s = severity.lower().strip()
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "unknown": Severity.UNKNOWN,
        "none": Severity.INFO,
        "neg": Severity.INFO,
        "neglectable": Severity.INFO,
    }
    return mapping.get(s, Severity.UNKNOWN)


def create_finding(
    tool: ToolName,
    title: str,
    target: str,
    severity: str | Severity = Severity.UNKNOWN,
    description: str = "",
    evidence: Optional[dict[str, Any]] = None,
    references: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
    raw_output: str = "",
) -> Finding:
    sev = severity if isinstance(severity, Severity) else normalize_severity(severity)
    return Finding(
        tool=tool,
        title=title,
        description=description,
        severity=sev,
        target=target,
        evidence=evidence or {},
        references=references or [],
        tags=tags or [],
        raw_output=raw_output,
    )@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    campaign_id: str = ''
    step_id: str = ''
    tool: str = ''
    vuln_type: str = ''
    title: str = ''
    description: str = ''
    host: str = ''
    port: Optional[int] = None
    parameter: str = ''
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss_vector: str = ''
    cvss_score: float = 0.0
    severity: Severity = Severity.UNKNOWN
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    status: str = 'open'
    dedup_hash: str = ''
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def compute_dedup_hash(self) -> str:
        import hashlib
        key = f'{self.vuln_type}|{self.host}|{self.port}|{self.parameter}'
        self.dedup_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.dedup_hash

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        data = data.copy()
        data['severity'] = Severity(data.get('severity', 'unknown'))
        return cls(**data)

@dataclass
class Vulnerability:
    finding: Finding
    exploit_available: bool = False
    exploit_code: str = ''
    exploit_references: List[str] = field(default_factory=list)
    remediation: str = ''
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['finding'] = self.finding.to_dict()
        return d

@dataclass
class ScanResult:
    tool: str
    target: str
    command: str
    raw_output: str
    parsed_hosts: List[Host] = field(default_factory=list)
    parsed_findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['parsed_hosts'] = [h.to_dict() for h in self.parsed_hosts]
        d['parsed_findings'] = [f.to_dict() for f in self.parsed_findings]
        return d

@dataclass
class CampaignStep:
    id: str
    tool: str
    args: List[str] = field(default_factory=list)
    parser: str = ''
    description: str = ''
    depends_on: List[str] = field(default_factory=list)
    condition: str = ''
    timeout: int = 300
    env: Dict[str, str] = field(default_factory=dict)
    state: StepState = StepState.PENDING
    result: Optional[ScanResult] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    def render_command(self, context: Dict[str, Any]) -> List[str]:
        rendered = []
        for arg in self.args:
            for key, value in context.items():
                if isinstance(value, list):
                    arg = arg.replace(f'{{{{{key}}}}}', ' '.join(str(v) for v in value))
                else:
                    arg = arg.replace(f'{{{{{key}}}}}', str(value))
            rendered.append(arg)
        return rendered

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['state'] = self.state.value
        if self.result:
            d['result'] = self.result.to_dict()
        return d

@dataclass
class ExecutionResult:
    step_id: str
    success: bool = False
    findings: List[Finding] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)
    raw_output: str = ''
    stderr: str = ''
    blocked: bool = False
    block_reason: str = ''
    timed_out: bool = False
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['findings'] = [f.to_dict() for f in self.findings]
        d['hosts'] = [h.to_dict() for h in self.hosts]
        return d

@dataclass
class Campaign:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ''
    name: str = ''
    description: str = ''
    steps: List[CampaignStep] = field(default_factory=list)
    state: CampaignState = CampaignState.PLANNING
    findings: List[Finding] = field(default_factory=list)
    scope_guard_config: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        finding.campaign_id = self.id
        finding.compute_dedup_hash()
        for existing in self.findings:
            if existing.dedup_hash == finding.dedup_hash:
                existing.evidence.update(finding.evidence)
                existing.updated_at = datetime.utcnow().isoformat()
                return
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def critical_high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['state'] = self.state.value
        d['steps'] = [s.to_dict() for s in self.steps]
        d['findings'] = [f.to_dict() for f in self.findings]
        d['scope_guard_config'] = self.scope_guard_config
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Campaign':
        data = data.copy()
        data['state'] = CampaignState(data.get('state', 'planning'))
        data['steps'] = [CampaignStep(**s) for s in data.get('steps', [])]
        data['findings'] = [Finding.from_dict(f) for f in data.get('findings', [])]
        return cls(**data)

def to_json(obj: Any) -> str:
    if hasattr(obj, 'to_dict'):
        return json.dumps(obj.to_dict(), indent=2, default=str)
    return json.dumps(obj, indent=2, default=str)

def from_json(json_str: str, cls: type) -> Any:
    data = json.loads(json_str)
    if hasattr(cls, 'from_dict'):
        return cls.from_dict(data)
    return cls(**data)
