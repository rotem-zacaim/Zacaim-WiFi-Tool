"""Dataclasses shared across the application."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CommandResult:
    name: str
    command: List[str]
    returncode: Optional[int]
    duration_seconds: float = 0.0
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    skipped: bool = False
    reason: Optional[str] = None


@dataclass
class ServiceFinding:
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    state: str = "open"

    @property
    def display_name(self) -> str:
        detail = " ".join(part for part in [self.product, self.version, self.extra_info] if part).strip()
        return f"{self.service} - {detail}" if detail else self.service


@dataclass
class HttpEndpoint:
    url: str
    title: str = ""
    server_header: str = ""
    status_code: str = ""
    reachable: bool = False
    security_headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    description: str
    evidence: List[str] = field(default_factory=list)
    follow_up: str = ""


@dataclass
class TargetSummary:
    target: str
    target_kind: str
    session_id: str
    profile: str
    started_at: str
    output_dir: str
    engagement_id: str = ""
    target_label: str = ""
    open_services: List[ServiceFinding] = field(default_factory=list)
    http_endpoints: List[HttpEndpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    os_guess: str = ""
    host_observations: Dict[str, Any] = field(default_factory=dict)
    web_observations: Dict[str, Any] = field(default_factory=dict)
    recommended_steps: List[str] = field(default_factory=list)
    command_results: List[CommandResult] = field(default_factory=list)
