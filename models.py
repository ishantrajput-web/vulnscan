"""Shared data models. Plain dataclasses -> trivially JSON-serialisable."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


@dataclass
class Vulnerability:
    cve_id: str
    description: str = ""
    cvss: Optional[float] = None
    severity: str = "info"
    source: str = "nvd"          # nvd | built-in
    url: str = ""


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    remediation: str = ""


@dataclass
class PortResult:
    port: int
    state: str = "open"
    protocol: str = "tcp"
    service: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    banner: str = ""
    tls: bool = False
    tls_version: Optional[str] = None
    tls_error: Optional[str] = None
    vulns: List[Vulnerability] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    alive: bool = True
    rtt_ms: Optional[float] = None
    ttl: Optional[int] = None
    os_guess: str = "Unknown"
    os_source: str = ""
    ports: List[PortResult] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "info"


@dataclass
class WebResult:
    """Passive analysis of one web origin (URL)."""
    url: str
    host_ip: str = ""                 # resolved IP (used to attach to a network host)
    standalone: bool = True           # True when scanned as a website (no network host owns it)
    final_url: str = ""
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    redirects: List[str] = field(default_factory=list)
    tls: Dict[str, Any] = field(default_factory=dict)
    techs: List[Dict[str, Any]] = field(default_factory=list)      # [{product, version, source}]
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    exposed: List[Dict[str, Any]] = field(default_factory=list)    # [{path, status, title}]
    dns: Dict[str, Any] = field(default_factory=dict)
    vulns: List[Vulnerability] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "info"
    error: Optional[str] = None


@dataclass
class ScanResult:
    scan_id: str
    tool_version: str
    targets: str
    started: str
    finished: str = ""
    duration_s: float = 0.0
    hosts: List[HostResult] = field(default_factory=list)
    webs: List[WebResult] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
