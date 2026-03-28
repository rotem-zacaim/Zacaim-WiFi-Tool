#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZACAIM V2

Authorized-use pentest workspace for labs, CTFs, and real engagements.
It focuses on discovery, fingerprinting, evidence collection, and reporting
for targets you are explicitly allowed to assess.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import threading
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

try:
    from rich.console import Console
    from rich.columns import Columns
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    Console = Any  # type: ignore[assignment]
    Columns = Panel = Rule = Table = None  # type: ignore[assignment]
    RICH_AVAILABLE = False


APP_NAME = "ZACAIM V2 - Pentest Workbench"
WEB_PORT_HINTS = {80, 81, 88, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888}
LIVE_FRAMES = ["[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]"]
MATRIX_GLYPHS = "01ABCDEF[]{}<>/$#@&*+=-"
BOOT_TOKENS = [
    "init_ui()",
    "load.sessions",
    "hydrate.targets",
    "sync.findings",
    "check.tools",
    "mount.workspace",
    "render.cli",
    "watch.live",
    "scan.web",
    "scan.host",
]
COMMON_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]
WEB_AUTOMATION_PROFILES = {
    "safe": ["http_probe", "httpx", "tls", "whatweb", "known_paths"],
    "standard": ["http_probe", "httpx", "tls", "whatweb", "wafw00f", "katana", "known_paths"],
    "deep": ["http_probe", "httpx", "tls", "whatweb", "wafw00f", "katana_deep", "testssl", "known_paths"],
}
KNOWN_WEB_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
]
DEFAULT_PROFILES = {
    "quick": ["nmap_quick", "http_probe"],
    "standard": ["nmap_standard", "http_probe", "tls_probe", "whatweb"],
    "deep": ["nmap_deep", "http_probe", "tls_probe", "whatweb"],
}
ADMIN_SERVICES = {"ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "winrm", "http-rpc-epmap"}
FILE_SERVICES = {"ftp", "tftp", "smb", "microsoft-ds", "netbios-ssn", "nfs"}
DATABASE_SERVICES = {"mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "oracle-tns", "oracle"}
BOOT_STATUS_LINES = [
    ("core", "mounting workspace graph"),
    ("intel", "hydrating discovery engine"),
    ("host", "binding multi-tool host pipeline"),
    ("web", "binding deep web automation"),
    ("ui", "forging operator console"),
]


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def resolve_app_dir() -> Path:
    candidates: List[Path] = []
    custom_home = os.environ.get("ZACAIM_HOME")
    if custom_home:
        candidates.append(Path(custom_home).expanduser())

    candidates.append(Path.home() / ".zacaim_v2")

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        candidates.append(Path(local_appdata) / "zacaim_v2")

    candidates.append(Path.cwd() / ".zacaim_v2")

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            continue

    raise PermissionError("Unable to create an application data directory for ZACAIM.")


APP_DIR = resolve_app_dir()
SESSIONS_DIR = APP_DIR / "sessions"
ENGAGEMENTS_DIR = APP_DIR / "engagements"
CONFIG_FILE = APP_DIR / "config.json"


@dataclass
class CommandResult:
    name: str
    command: List[str]
    returncode: Optional[int]
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


def ensure_app_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "item"


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def write_text(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def append_unique(items: List[str], *values: str) -> None:
    for value in values:
        candidate = value.strip()
        if candidate and candidate not in items:
            items.append(candidate)


def normalize_url(raw_value: str) -> Dict[str, Any]:
    candidate = raw_value.strip()
    if not candidate:
        raise ValueError("URL cannot be empty.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Provide a valid http/https URL.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    netloc = parsed.netloc or f"{parsed.hostname}:{port}"
    url = f"{parsed.scheme}://{netloc}{path}"
    return {
        "url": url,
        "host": parsed.hostname,
        "port": port,
        "scheme": parsed.scheme,
        "path": path,
    }


class LiveStatus:
    def __init__(self, message: str, success_message: str = ""):
        self.message = message
        self.success_message = success_message or message
        self.enabled = sys.stdout.isatty()
        self.rich_enabled = RICH_AVAILABLE and self.enabled
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started_at = time.time()
        self._rich_console = Console() if self.rich_enabled else None
        self._rich_status: Any = None

    def _render(self) -> None:
        frame_index = 0
        while not self._stop.is_set():
            elapsed = time.time() - self._started_at
            frame = LIVE_FRAMES[frame_index % len(LIVE_FRAMES)]
            sys.stdout.write(
                f"\r{Colors.CYAN}{frame}{Colors.RESET} {self.message} "
                f"{Colors.YELLOW}{elapsed:>4.1f}s{Colors.RESET}"
            )
            sys.stdout.flush()
            frame_index += 1
            time.sleep(0.12)

        sys.stdout.write("\r" + (" " * 96) + "\r")
        sys.stdout.flush()

    def __enter__(self) -> "LiveStatus":
        if self.rich_enabled and self._rich_console is not None:
            self._rich_status = self._rich_console.status(f"[bold cyan]{self.message}[/bold cyan]", spinner="dots")
            self._rich_status.__enter__()
        elif self.enabled:
            self._thread = threading.Thread(target=self._render, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, _: Any) -> None:
        if self._rich_status is not None:
            self._rich_status.__exit__(exc_type, exc, _)
        elif self.enabled:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=0.5)
        if self.rich_enabled and self._rich_console is not None:
            label = "[green]ready[/green]" if exc is None else "[red]error[/red]"
            self._rich_console.print(f"{label} {self.success_message}")
        else:
            color = Colors.GREEN if exc is None else Colors.RED
            label = "ready" if exc is None else "error"
            print(f"{color}[{label}]{Colors.RESET} {self.success_message}")


class TargetValidator:
    HOST_RE = re.compile(r"^[a-zA-Z0-9.-]+$")

    @classmethod
    def normalize(cls, raw_target: str) -> str:
        target = raw_target.strip()
        if not target:
            raise ValueError("Target cannot be empty.")

        try:
            return str(ipaddress.ip_address(target))
        except ValueError:
            pass

        if not cls.HOST_RE.match(target):
            raise ValueError("Target must be a valid IP address or hostname.")

        return target

    @staticmethod
    def kind(target: str) -> str:
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            return "hostname"


class WorkspaceManager:
    def create_session(self, target: str, profile: str, sessions_root: Optional[Path] = None) -> Path:
        root = sessions_root or SESSIONS_DIR
        root.mkdir(parents=True, exist_ok=True)
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = slugify(target)
        session_dir = root / f"{session_id}_{target_slug}_{profile}"
        session_dir.mkdir(parents=True, exist_ok=True)
        for child in ["artifacts", "reports", "raw"]:
            (session_dir / child).mkdir(exist_ok=True)
        return session_dir


class CommandRunner:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def tool_available(self, name: str) -> bool:
        return shutil.which(name) is not None

    def run(
        self,
        name: str,
        command: List[str],
        artifact_prefix: str,
        timeout: int = 1800,
        required_tool: Optional[str] = None,
    ) -> CommandResult:
        required_tool = required_tool or command[0]
        stdout_path = self.base_dir / "artifacts" / f"{artifact_prefix}.stdout.txt"
        stderr_path = self.base_dir / "artifacts" / f"{artifact_prefix}.stderr.txt"

        if not self.tool_available(required_tool):
            message = f"Skipped: required tool '{required_tool}' is not installed."
            write_text(stdout_path, "")
            write_text(stderr_path, message)
            return CommandResult(
                name=name,
                command=command,
                returncode=None,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                skipped=True,
                reason=message,
            )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            write_text(stdout_path, completed.stdout)
            write_text(stderr_path, completed.stderr)
            return CommandResult(
                name=name,
                command=command,
                returncode=completed.returncode,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
            )
        except subprocess.TimeoutExpired as exc:
            stdout_data = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr_data = exc.stderr if isinstance(exc.stderr, str) else ""
            write_text(stdout_path, stdout_data)
            write_text(stderr_path, stderr_data or "Timed out.")
            return CommandResult(
                name=name,
                command=command,
                returncode=None,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                skipped=True,
                reason=f"Timed out after {timeout} seconds.",
            )


class HealthChecker:
    REQUIRED_TOOLS = ["nmap", "curl"]
    OPTIONAL_TOOLS = [
        "openssl",
        "whatweb",
        "httpx",
        "katana",
        "wafw00f",
        "testssl.sh",
        "dig",
        "host",
        "ssh-keyscan",
        "iw",
        "nmcli",
    ]

    @classmethod
    def run(cls) -> Dict[str, Any]:
        ensure_app_dirs()
        tool_status = {tool: shutil.which(tool) or "" for tool in cls.REQUIRED_TOOLS + cls.OPTIONAL_TOOLS}
        payload = {
            "app": APP_NAME,
            "python": sys.version.split()[0],
            "hostname": socket.gethostname(),
            "root": is_root(),
            "sessions_dir": str(SESSIONS_DIR),
            "engagements_dir": str(ENGAGEMENTS_DIR),
            "tools": tool_status,
        }
        write_json(CONFIG_FILE, payload)
        return payload


class WifiInspector:
    @staticmethod
    def run() -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "tools": {
                "iw": shutil.which("iw") or "",
                "nmcli": shutil.which("nmcli") or "",
            },
            "interfaces": [],
            "note": "Wireless support in V2 is limited to local adapter status and workspace readiness.",
        }

        if payload["tools"]["iw"]:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            current: Dict[str, str] = {}
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if line.startswith("Interface "):
                    if current:
                        payload["interfaces"].append(current)
                    current = {"name": line.split(" ", 1)[1]}
                elif line.startswith("type ") and current:
                    current["type"] = line.split(" ", 1)[1]
                elif line.startswith("channel ") and current:
                    current["channel"] = line.split(" ", 1)[1]
            if current:
                payload["interfaces"].append(current)

        if payload["tools"]["nmcli"]:
            result = subprocess.run(
                ["nmcli", "--terse", "--fields", "DEVICE,TYPE,STATE", "device", "status"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            states: Dict[str, str] = {}
            for line in result.stdout.splitlines():
                device, device_type, state = (line.split(":", 2) + ["", "", ""])[:3]
                if device_type == "wifi":
                    states[device] = state
            for interface in payload["interfaces"]:
                interface["state"] = states.get(interface.get("name", ""), "unknown")

        return payload


class NmapParser:
    @staticmethod
    def parse(xml_path: Path) -> Dict[str, Any]:
        result = {"services": [], "os_guess": ""}
        if not xml_path.exists():
            return result

        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return result

        host = root.find("host")
        if host is None:
            return result

        os_match = host.find("./os/osmatch")
        if os_match is not None:
            result["os_guess"] = os_match.attrib.get("name", "")

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            service = port.find("service")
            result["services"].append(
                ServiceFinding(
                    port=int(port.attrib.get("portid", "0")),
                    protocol=port.attrib.get("protocol", "tcp"),
                    service=service.attrib.get("name", "unknown") if service is not None else "unknown",
                    product=service.attrib.get("product", "") if service is not None else "",
                    version=service.attrib.get("version", "") if service is not None else "",
                    extra_info=service.attrib.get("extrainfo", "") if service is not None else "",
                    tunnel=service.attrib.get("tunnel", "") if service is not None else "",
                )
            )

        return result


class FindingsAnalyzer:
    @staticmethod
    def generate(summary: TargetSummary) -> List[Finding]:
        findings: List[Finding] = []
        ports = {service.port for service in summary.open_services}
        host_observations = summary.host_observations or {}
        web_observations = summary.web_observations or {}

        if summary.os_guess:
            findings.append(
                Finding(
                    title="Possible operating system fingerprint",
                    severity="info",
                    category="fingerprint",
                    description=f"Nmap OS detection suggested: {summary.os_guess}.",
                    evidence=[summary.os_guess],
                    follow_up="Validate with service behavior and host-specific enumeration.",
                )
            )

        if host_observations.get("reverse_dns"):
            findings.append(
                Finding(
                    title="Reverse DNS name discovered",
                    severity="info",
                    category="fingerprint",
                    description="The IP target resolved to one or more reverse-DNS names during host enrichment.",
                    evidence=host_observations.get("reverse_dns", [])[:3],
                    follow_up="Compare PTR names with service banners, TLS certificates, and scope records.",
                )
            )

        if host_observations.get("ssh_host_keys"):
            findings.append(
                Finding(
                    title="SSH host keys collected",
                    severity="info",
                    category="access",
                    description="SSH key material was collected for one or more exposed SSH services.",
                    evidence=host_observations.get("ssh_host_keys", [])[:3],
                    follow_up="Review key algorithms and hostnames for fleet identification and hardening validation.",
                )
            )

        if host_observations.get("tls_highlights"):
            findings.append(
                Finding(
                    title="TLS metadata captured for one or more services",
                    severity="info",
                    category="web",
                    description="The deep host profile captured TLS-related output that may help guide service review.",
                    evidence=host_observations.get("tls_highlights", [])[:4],
                    follow_up="Review the TLS artifact output for protocol, certificate, and cipher details.",
                )
            )

        if summary.http_endpoints:
            endpoints = ", ".join(endpoint.url for endpoint in summary.http_endpoints)
            findings.append(
                Finding(
                    title="Web surface identified",
                    severity="info",
                    category="web",
                    description="One or more HTTP/S endpoints were identified and fingerprinted.",
                    evidence=[endpoints],
                    follow_up="Review titles, headers, and technologies to choose the next web-focused checks.",
                )
            )

        for endpoint in summary.http_endpoints:
            if not endpoint.reachable:
                findings.append(
                    Finding(
                        title=f"Web probe did not complete for {endpoint.url}",
                        severity="info",
                        category="web",
                        description="The endpoint did not return a successful HTTP response during the probe window.",
                        evidence=[endpoint.url],
                        follow_up="Verify reachability, DNS resolution, egress policy, and whether the target requires a different path or Host header.",
                    )
                )
                continue

            endpoint_evidence = [endpoint.url]
            if endpoint.status_code:
                endpoint_evidence.append(f"status={endpoint.status_code}")
                findings.append(
                    Finding(
                        title=f"HTTP response observed from {endpoint.url}",
                        severity="info",
                        category="web",
                        description=f"The endpoint responded with HTTP status {endpoint.status_code}.",
                        evidence=endpoint_evidence,
                        follow_up="Review reachable content, redirects, and authentication behavior.",
                    )
                )

            if endpoint.server_header:
                findings.append(
                    Finding(
                        title=f"Server header exposed for {endpoint.url}",
                        severity="info",
                        category="web",
                        description="The web response disclosed a server banner/header value.",
                        evidence=[endpoint.url, f"server={endpoint.server_header}"],
                        follow_up="Validate whether the disclosed server stack matches the observed behavior and hardening baseline.",
                    )
                )

            if endpoint.technologies:
                findings.append(
                    Finding(
                        title=f"Technology fingerprint captured for {endpoint.url}",
                        severity="info",
                        category="web",
                        description="The endpoint returned technology indicators from the web fingerprinting pass.",
                        evidence=[endpoint.url, endpoint.technologies[0]],
                        follow_up="Use the identified stack to drive product-specific validation steps and version review.",
                    )
                )

            if endpoint.url.startswith("https://") and not endpoint.security_headers:
                findings.append(
                    Finding(
                        title=f"Common security headers were not observed for {endpoint.url}",
                        severity="info",
                        category="web",
                        description="The HTTPS response did not expose the common browser hardening headers this tool checks for.",
                        evidence=[endpoint.url, "missing=HSTS/CSP/XFO/XCTO/Referrer-Policy"],
                        follow_up="Confirm the application or reverse proxy header policy manually before drawing conclusions.",
                    )
                )

        if web_observations.get("waf"):
            findings.append(
                Finding(
                    title="Web application firewall or WAAP identified",
                    severity="info",
                    category="web",
                    description="The web automation stack identified a possible WAF/WAAP in front of the target.",
                    evidence=[str(web_observations["waf"])],
                    follow_up="Account for the enforcement layer when interpreting reachability and response behavior.",
                )
            )

        crawl_url_count = int(web_observations.get("crawl_url_count", 0) or 0)
        if crawl_url_count >= 20:
            findings.append(
                Finding(
                    title="Broad crawlable web surface observed",
                    severity="info",
                    category="web",
                    description=f"The crawler discovered {crawl_url_count} in-scope URLs, suggesting a larger application surface.",
                    evidence=web_observations.get("crawl_sample", [])[:5],
                    follow_up="Cluster the discovered routes by function and review auth boundaries, admin areas, and API paths.",
                )
            )

        path_hits = web_observations.get("path_hits", [])
        if "/robots.txt" in path_hits:
            findings.append(
                Finding(
                    title="robots.txt exposed crawler guidance",
                    severity="info",
                    category="web",
                    description="robots.txt was reachable and may contain useful site structure hints.",
                    evidence=[f"{summary.target.rstrip('/')}/robots.txt"],
                    follow_up="Review robots directives for sensitive or admin-adjacent routes before deeper manual validation.",
                )
            )
        if "/sitemap.xml" in path_hits:
            findings.append(
                Finding(
                    title="sitemap.xml exposed route inventory",
                    severity="info",
                    category="web",
                    description="sitemap.xml was reachable and may contain additional application routes or content areas.",
                    evidence=[f"{summary.target.rstrip('/')}/sitemap.xml"],
                    follow_up="Use the sitemap as a coverage baseline for manual review and authenticated testing.",
                )
            )

        interesting_urls = [str(item) for item in web_observations.get("interesting_urls", [])]
        if any("graphql" in url.lower() for url in interesting_urls):
            findings.append(
                Finding(
                    title="Potential GraphQL endpoint discovered",
                    severity="info",
                    category="web",
                    description="The web discovery phase observed a URL containing GraphQL-style naming.",
                    evidence=[url for url in interesting_urls if "graphql" in url.lower()][:3],
                    follow_up="Confirm schema exposure, introspection behavior, and access controls in a scoped API review.",
                )
            )

        if any(url.lower().endswith(("openapi.json", "swagger.json")) for url in interesting_urls):
            findings.append(
                Finding(
                    title="Potential API documentation artifact discovered",
                    severity="info",
                    category="web",
                    description="The crawler or known-path checks observed a likely API description document.",
                    evidence=[
                        url
                        for url in interesting_urls
                        if url.lower().endswith(("openapi.json", "swagger.json"))
                    ][:3],
                    follow_up="Review the exposed specification to map routes, auth schemes, and data models.",
                )
            )

        if host_observations.get("service_groups", {}).get("web", 0) >= 2:
            findings.append(
                Finding(
                    title="Multiple web-facing services identified",
                    severity="info",
                    category="web",
                    description="The target exposes more than one HTTP/S-like service, suggesting a broader application footprint.",
                    evidence=[f"web_ports={host_observations['service_groups']['web']}"],
                    follow_up="Compare the discovered web services for shared auth boundaries, admin paths, and stack differences.",
                )
            )

        if {88, 389, 445}.issubset(ports) or {53, 88, 389}.issubset(ports):
            findings.append(
                Finding(
                    title="Possible Active Directory footprint",
                    severity="info",
                    category="windows",
                    description="The combination of open ports suggests the host may be part of AD infrastructure.",
                    evidence=[f"Observed ports: {', '.join(str(port) for port in sorted(ports))}"],
                    follow_up="Validate hostname, SMB banners, LDAP responses, and Kerberos-related services.",
                )
            )

        for service in summary.open_services:
            service_name = service.service.lower()
            evidence = [f"{service.port}/{service.protocol} -> {service.display_name}"]

            if service_name in ADMIN_SERVICES:
                findings.append(
                    Finding(
                        title=f"Administrative service exposed on {service.port}",
                        severity="info",
                        category="access",
                        description=f"The target exposes {service.service} on port {service.port}.",
                        evidence=evidence,
                        follow_up="Assess access controls, authentication methods, and banner information.",
                    )
                )

            if service_name in FILE_SERVICES:
                findings.append(
                    Finding(
                        title=f"File transfer or share service exposed on {service.port}",
                        severity="info",
                        category="files",
                        description=f"The target exposes {service.service}, which may provide accessible files or shares.",
                        evidence=evidence,
                        follow_up="Enumerate shares, permissions, anonymous access, and file metadata where authorized.",
                    )
                )

            if service_name in DATABASE_SERVICES:
                findings.append(
                    Finding(
                        title=f"Database service exposed on {service.port}",
                        severity="info",
                        category="database",
                        description=f"The target appears to expose {service.service}.",
                        evidence=evidence,
                        follow_up="Review network exposure, authentication requirements, and version-specific documentation.",
                    )
                )

            if service.product or service.version:
                findings.append(
                    Finding(
                        title=f"Version fingerprint captured for port {service.port}",
                        severity="info",
                        category="fingerprint",
                        description="Service banner data includes product and/or version details.",
                        evidence=evidence,
                        follow_up="Compare the identified version with vendor guidance and internal testing playbooks.",
                    )
                )

        deduped: List[Finding] = []
        seen: set[tuple[str, str]] = set()
        for finding in findings:
            marker = (finding.title, finding.description)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(finding)
        return deduped


class ReportBuilder:
    @staticmethod
    def build(summary: TargetSummary, session_dir: Path) -> Dict[str, str]:
        reports_dir = session_dir / "reports"
        summary_path = reports_dir / "summary.json"
        report_path = reports_dir / "report.md"
        findings_path = reports_dir / "findings.json"

        write_json(summary_path, asdict(summary))
        write_json(findings_path, [asdict(finding) for finding in summary.findings])

        lines = [
            f"# {APP_NAME}",
            "",
            "## Scope",
            f"- Target: `{summary.target}`",
            f"- Target type: `{summary.target_kind}`",
            f"- Profile: `{summary.profile}`",
            f"- Started: `{summary.started_at}`",
            f"- Output dir: `{summary.output_dir}`",
        ]

        if summary.engagement_id:
            lines.append(f"- Engagement: `{summary.engagement_id}`")
        if summary.target_label:
            lines.append(f"- Target label: `{summary.target_label}`")

        lines.extend(["", "## Service Summary"])
        if summary.open_services:
            for service in summary.open_services:
                lines.append(f"- `{service.port}/{service.protocol}` -> `{service.display_name}`")
        else:
            lines.append("- No open services were parsed from the scan output.")

        if summary.host_observations:
            host_obs = summary.host_observations
            lines.extend(["", "## Host Automation"])
            if host_obs.get("service_groups"):
                groups = ", ".join(f"{key}={value}" for key, value in host_obs["service_groups"].items())
                lines.append(f"- Service groups: `{groups}`")
            if host_obs.get("reverse_dns"):
                lines.append(f"- Reverse DNS: `{', '.join(host_obs['reverse_dns'])}`")
            for item in host_obs.get("ssh_host_keys", [])[:6]:
                lines.append(f"  ssh-key: {item}")
            for line in host_obs.get("tls_highlights", [])[:6]:
                lines.append(f"  tls-highlight: {line}")

        lines.extend(["", "## Web Summary"])
        if summary.http_endpoints:
            for endpoint in summary.http_endpoints:
                notes = "; ".join(endpoint.notes) if endpoint.notes else "No extra notes."
                technologies = ", ".join(endpoint.technologies) if endpoint.technologies else "n/a"
                security_headers = (
                    ", ".join(sorted(endpoint.security_headers))
                    if endpoint.security_headers
                    else "n/a"
                )
                lines.append(
                    f"- `{endpoint.url}` | status: `{endpoint.status_code or 'n/a'}` | "
                    f"title: `{endpoint.title or 'n/a'}` | server: `{endpoint.server_header or 'n/a'}` | "
                    f"technologies: `{technologies}` | security-headers: `{security_headers}` | notes: {notes}"
                )
        else:
            lines.append("- No web endpoints were identified.")

        if summary.web_observations:
            observations = summary.web_observations
            lines.extend(["", "## Web Automation"])
            lines.append(f"- Profile: `{observations.get('profile', 'n/a')}`")
            if observations.get("resolved_host"):
                lines.append(f"- Resolved host: `{observations['resolved_host']}`")
            if observations.get("cdn"):
                lines.append(f"- CDN / edge hint: `{observations['cdn']}`")
            if observations.get("waf"):
                lines.append(f"- WAF / WAAP hint: `{observations['waf']}`")
            if observations.get("content_types"):
                lines.append(f"- Content types: `{', '.join(observations['content_types'])}`")
            if observations.get("path_hits"):
                lines.append(f"- Reachable known paths: `{', '.join(observations['path_hits'])}`")
            if observations.get("crawl_url_count"):
                lines.append(f"- Crawl URL count: `{observations['crawl_url_count']}`")
            for url in observations.get("crawl_sample", [])[:10]:
                lines.append(f"  crawl-sample: {url}")
            for line in observations.get("testssl_highlights", [])[:6]:
                lines.append(f"  tls-highlight: {line}")

        if summary.recommended_steps:
            lines.extend(["", "## Recommended Next Steps"])
            for step in summary.recommended_steps:
                lines.append(f"- {step}")

        lines.extend(["", "## Findings And Leads"])
        if summary.findings:
            for finding in summary.findings:
                lines.append(f"- [{finding.severity}] {finding.title}: {finding.description}")
                if finding.evidence:
                    lines.append(f"  evidence: {' | '.join(finding.evidence)}")
                if finding.follow_up:
                    lines.append(f"  follow-up: {finding.follow_up}")
        else:
            lines.append("- No structured findings were generated.")

        lines.extend(["", "## Command Results"])
        for result in summary.command_results:
            status = "skipped" if result.skipped else f"exit {result.returncode}"
            lines.append(f"- `{result.name}` -> {status}")
            if result.reason:
                lines.append(f"  reason: {result.reason}")

        write_text(report_path, "\n".join(lines) + "\n")
        return {
            "summary_json": str(summary_path),
            "report_md": str(report_path),
            "findings_json": str(findings_path),
        }


class EngagementManager:
    def __init__(self) -> None:
        ensure_app_dirs()

    def create(self, name: str, description: str = "", scope: str = "") -> Dict[str, Any]:
        engagement_id = slugify(name)
        engagement_dir = ENGAGEMENTS_DIR / engagement_id
        if engagement_dir.exists():
            raise ValueError(f"Engagement '{engagement_id}' already exists.")

        for child in ["targets", "sessions", "reports"]:
            (engagement_dir / child).mkdir(parents=True, exist_ok=True)

        metadata = {
            "id": engagement_id,
            "name": name,
            "description": description,
            "scope": scope,
            "created_at": now_iso(),
        }
        write_json(engagement_dir / "engagement.json", metadata)
        write_json(engagement_dir / "targets.json", [])
        return metadata

    def list_engagements(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for path in sorted(ENGAGEMENTS_DIR.iterdir()) if ENGAGEMENTS_DIR.exists() else []:
            metadata = read_json(path / "engagement.json", {})
            if metadata:
                results.append(metadata)
        return results

    def get_engagement_dir(self, engagement_id: str) -> Path:
        path = ENGAGEMENTS_DIR / slugify(engagement_id)
        if not path.exists():
            raise ValueError(f"Engagement '{engagement_id}' does not exist.")
        return path

    def load_metadata(self, engagement_id: str) -> Dict[str, Any]:
        engagement_dir = self.get_engagement_dir(engagement_id)
        metadata = read_json(engagement_dir / "engagement.json", {})
        if not metadata:
            raise ValueError(f"Engagement '{engagement_id}' is missing metadata.")
        return metadata

    def load_targets(self, engagement_id: str) -> List[Dict[str, Any]]:
        engagement_dir = self.get_engagement_dir(engagement_id)
        return read_json(engagement_dir / "targets.json", [])

    def save_targets(self, engagement_id: str, targets: List[Dict[str, Any]]) -> None:
        engagement_dir = self.get_engagement_dir(engagement_id)
        write_json(engagement_dir / "targets.json", targets)

    def add_target(
        self,
        engagement_id: str,
        address: str,
        name: str = "",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        tags = tags or []
        targets = self.load_targets(engagement_id)
        normalized = TargetValidator.normalize(address)

        for target in targets:
            if target["address"] == normalized:
                raise ValueError(f"Target '{normalized}' already exists in this engagement.")

        base_id = slugify(name or normalized)
        target_id = base_id
        counter = 2
        existing_ids = {target["target_id"] for target in targets}
        while target_id in existing_ids:
            target_id = f"{base_id}_{counter}"
            counter += 1

        engagement_dir = self.get_engagement_dir(engagement_id)
        target_dir = engagement_dir / "targets" / target_id
        for child in ["notes", "evidence", "reports"]:
            (target_dir / child).mkdir(parents=True, exist_ok=True)

        target_record = {
            "target_id": target_id,
            "name": name or normalized,
            "address": normalized,
            "kind": TargetValidator.kind(normalized),
            "tags": tags,
            "created_at": now_iso(),
            "note_count": 0,
            "evidence_count": 0,
            "last_scan_at": "",
            "last_profile": "",
            "last_session": "",
            "service_count": 0,
            "http_count": 0,
            "findings_count": 0,
            "os_guess": "",
        }

        write_json(target_dir / "notes" / "notes.json", [])
        write_json(target_dir / "evidence" / "evidence.json", [])
        targets.append(target_record)
        self.save_targets(engagement_id, targets)
        return target_record

    def resolve_target(self, engagement_id: str, identifier: str) -> Dict[str, Any]:
        targets = self.load_targets(engagement_id)
        normalized = identifier.strip()
        for target in targets:
            if normalized in {target["target_id"], target["address"], target["name"]}:
                return target
        raise ValueError(f"Target '{identifier}' was not found in engagement '{engagement_id}'.")

    def add_note(
        self,
        engagement_id: str,
        target_ref: str,
        text: str,
        category: str = "note",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        tags = tags or []
        target = self.resolve_target(engagement_id, target_ref)
        target_dir = self.get_engagement_dir(engagement_id) / "targets" / target["target_id"]
        notes_path = target_dir / "notes" / "notes.json"
        notes = read_json(notes_path, [])
        entry = {
            "id": f"note_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "created_at": now_iso(),
            "category": category,
            "tags": tags,
            "text": text,
        }
        notes.append(entry)
        write_json(notes_path, notes)
        self._update_target_counter(engagement_id, target["target_id"], "note_count", len(notes))
        return entry

    def add_evidence(
        self,
        engagement_id: str,
        target_ref: str,
        description: str = "",
        text: str = "",
        file_path: str = "",
    ) -> Dict[str, Any]:
        if not text and not file_path:
            raise ValueError("Provide either evidence text or a file path.")

        target = self.resolve_target(engagement_id, target_ref)
        target_dir = self.get_engagement_dir(engagement_id) / "targets" / target["target_id"]
        evidence_dir = target_dir / "evidence"
        evidence_index_path = evidence_dir / "evidence.json"
        evidence_entries = read_json(evidence_index_path, [])
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        entry: Dict[str, Any] = {
            "id": f"evidence_{stamp}",
            "created_at": now_iso(),
            "description": description,
            "type": "text" if text else "file",
        }

        if text:
            stored_file = evidence_dir / f"{stamp}_note.txt"
            write_text(stored_file, text)
            entry["stored_path"] = str(stored_file)

        if file_path:
            source = Path(file_path).expanduser()
            if not source.exists() or not source.is_file():
                raise ValueError(f"Evidence file '{file_path}' was not found.")
            destination = evidence_dir / f"{stamp}_{source.name}"
            shutil.copy2(source, destination)
            entry["source_path"] = str(source)
            entry["stored_path"] = str(destination)

        evidence_entries.append(entry)
        write_json(evidence_index_path, evidence_entries)
        self._update_target_counter(engagement_id, target["target_id"], "evidence_count", len(evidence_entries))
        return entry

    def update_target_after_scan(
        self,
        engagement_id: str,
        target_id: str,
        summary: TargetSummary,
        reports: Dict[str, str],
    ) -> None:
        targets = self.load_targets(engagement_id)
        for target in targets:
            if target["target_id"] != target_id:
                continue
            target["last_scan_at"] = summary.started_at
            target["last_profile"] = summary.profile
            target["last_session"] = summary.session_id
            target["service_count"] = len(summary.open_services)
            target["http_count"] = len(summary.http_endpoints)
            target["findings_count"] = len(summary.findings)
            target["os_guess"] = summary.os_guess
            break
        self.save_targets(engagement_id, targets)

        target_dir = self.get_engagement_dir(engagement_id) / "targets" / target_id / "reports"
        write_json(target_dir / "latest_summary.json", asdict(summary))
        write_json(target_dir / "latest_findings.json", [asdict(finding) for finding in summary.findings])
        report_text = Path(reports["report_md"]).read_text(encoding="utf-8", errors="replace")
        write_text(target_dir / "latest_report.md", report_text)

    def _update_target_counter(self, engagement_id: str, target_id: str, field_name: str, value: int) -> None:
        targets = self.load_targets(engagement_id)
        for target in targets:
            if target["target_id"] == target_id:
                target[field_name] = value
                break
        self.save_targets(engagement_id, targets)


class TargetScanner:
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.runner = CommandRunner(session_dir)

    def scan(self, raw_target: str, profile: str) -> TargetSummary:
        target = TargetValidator.normalize(raw_target)
        summary = TargetSummary(
            target=target,
            target_kind=TargetValidator.kind(target),
            session_id=self.session_dir.name,
            profile=profile,
            started_at=now_iso(),
            output_dir=str(self.session_dir),
            host_observations={
                "reverse_dns": [],
                "ssh_host_keys": [],
                "tls_highlights": [],
                "service_groups": {},
                "tool_notes": [],
            },
            web_observations={
                "profile": "embedded-host-enrichment",
                "interesting_urls": [],
                "related_hosts": [],
                "content_types": [],
                "waf": "",
                "crawl_url_count": 0,
                "crawl_sample": [],
                "path_hits": [],
                "testssl_highlights": [],
                "tool_notes": [],
            },
        )

        xml_path = self.session_dir / "raw" / "nmap.xml"
        text_path = self.session_dir / "raw" / "nmap.txt"
        nmap_command = self._build_nmap_command(profile, target, xml_path, text_path)
        summary.command_results.append(
            self.runner.run(
                name=f"nmap_{profile}",
                command=nmap_command,
                artifact_prefix=f"nmap_{profile}",
                timeout=3600,
                required_tool="nmap",
            )
        )

        parsed = NmapParser.parse(xml_path)
        summary.open_services = parsed["services"]
        summary.os_guess = parsed["os_guess"]
        summary.host_observations["service_groups"] = self._service_group_counts(summary.open_services)
        self._probe_reverse_dns(target, summary)
        self._probe_ssh_keys(target, summary.open_services, summary)

        web_helper = WebScanner(self.session_dir)
        for endpoint in self._identify_http_endpoints(target, summary.open_services):
            self._probe_http_endpoint(endpoint, summary)
            self._probe_tls(endpoint, summary)
            self._probe_whatweb(endpoint, summary)
            web_helper._probe_httpx(endpoint, summary)
            if profile in {"standard", "deep"}:
                web_helper._probe_known_paths(endpoint, summary)
                web_helper._probe_wafw00f(endpoint, summary)
            if profile == "deep":
                web_helper._probe_katana(endpoint, summary, deep=True)
                web_helper._probe_testssl(endpoint, summary)

        summary.host_observations["tls_highlights"] = list(summary.web_observations.get("testssl_highlights", []))
        summary.recommended_steps = self._recommended_steps(summary)

        summary.findings = FindingsAnalyzer.generate(summary)
        return summary

    def _build_nmap_command(self, profile: str, target: str, xml_path: Path, text_path: Path) -> List[str]:
        base = ["nmap", "-Pn", "--open", "-oX", str(xml_path), "-oN", str(text_path)]
        if profile == "quick":
            return base + ["-sV", target]
        if profile == "deep":
            flags = ["-sV", "-sC", "--version-all", "-O"]
            if not is_root():
                flags.remove("-O")
            return base + flags + [target]
        return base + ["-sV", "-sC", target]

    def _service_group_counts(self, services: List[ServiceFinding]) -> Dict[str, int]:
        counts = {"web": 0, "admin": 0, "files": 0, "database": 0}
        for service in services:
            service_name = service.service.lower()
            if "http" in service_name or service.port in WEB_PORT_HINTS or service.tunnel.lower() == "ssl":
                counts["web"] += 1
            if service_name in ADMIN_SERVICES:
                counts["admin"] += 1
            if service_name in FILE_SERVICES:
                counts["files"] += 1
            if service_name in DATABASE_SERVICES:
                counts["database"] += 1
        return counts

    def _probe_reverse_dns(self, target: str, summary: TargetSummary) -> None:
        if TargetValidator.kind(target) != "ip":
            return

        dig_result = self.runner.run(
            name="reverse_dns_dig",
            command=["dig", "+short", "-x", target],
            artifact_prefix="reverse_dns_dig",
            timeout=20,
            required_tool="dig",
        )
        host_result = self.runner.run(
            name="reverse_dns_host",
            command=["host", target],
            artifact_prefix="reverse_dns_host",
            timeout=20,
            required_tool="host",
        )
        summary.command_results.extend([dig_result, host_result])

        names: List[str] = []
        for result in [dig_result, host_result]:
            if not result.stdout_path or not Path(result.stdout_path).exists():
                continue
            for raw_line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip().rstrip(".")
                if not line:
                    continue
                if "domain name pointer" in line:
                    line = line.split("pointer", 1)[1].strip().rstrip(".")
                append_unique(names, line)

        summary.host_observations["reverse_dns"] = names

    def _probe_ssh_keys(self, target: str, services: List[ServiceFinding], summary: TargetSummary) -> None:
        ssh_ports = sorted({service.port for service in services if service.service.lower() == "ssh" or service.port == 22})
        keys: List[str] = []
        for port in ssh_ports:
            prefix = f"ssh_keyscan_{port}"
            result = self.runner.run(
                name=prefix,
                command=["ssh-keyscan", "-T", "6", "-p", str(port), target],
                artifact_prefix=prefix,
                timeout=20,
                required_tool="ssh-keyscan",
            )
            summary.command_results.append(result)
            if result.returncode not in {0, 1} or not result.stdout_path or not Path(result.stdout_path).exists():
                continue
            for raw_line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    append_unique(keys, f"{parts[0]} {parts[1]}")

        summary.host_observations["ssh_host_keys"] = keys

    def _recommended_steps(self, summary: TargetSummary) -> List[str]:
        steps: List[str] = []
        groups = summary.host_observations.get("service_groups", {})
        if groups.get("web"):
            steps.append("Review each discovered web endpoint separately and compare stack, headers, TLS, and reachable paths.")
        if groups.get("admin"):
            steps.append("Validate exposed administrative services against scope, expected management paths, and hardening baselines.")
        if groups.get("files"):
            steps.append("Review exposed file-sharing services for segmentation, access model, and banner consistency.")
        if groups.get("database"):
            steps.append("Confirm database exposure is expected and compare version fingerprints with the authorized architecture.")
        if summary.host_observations.get("reverse_dns"):
            steps.append("Use reverse-DNS names to pivot into certificate names, host inventory, and engagement notes.")
        if summary.web_observations.get("crawl_url_count", 0) >= 20:
            steps.append("The host appears to expose a large crawlable web surface. Prioritize admin, auth, API, and debug-style routes.")
        if not steps:
            steps.append("Review the captured host and service artifacts to decide which exposed services need deeper manual validation.")
        return steps

    def _identify_http_endpoints(self, target: str, services: List[ServiceFinding]) -> List[HttpEndpoint]:
        endpoints: List[HttpEndpoint] = []
        for service in services:
            service_name = service.service.lower()
            looks_like_web = (
                "http" in service_name
                or service.port in WEB_PORT_HINTS
                or service.tunnel.lower() == "ssl"
            )
            if not looks_like_web:
                continue

            scheme = "https" if service.tunnel.lower() == "ssl" or service.port in {443, 8443} else "http"
            endpoints.append(HttpEndpoint(url=f"{scheme}://{target}:{service.port}"))
        return endpoints

    def _probe_http_endpoint(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        prefix = slugify(endpoint.url)
        header_result = self.runner.run(
            name=f"http_headers_{prefix}",
            command=["curl", "-kI", "-L", "--max-time", "12", endpoint.url],
            artifact_prefix=f"http_headers_{prefix}",
            timeout=30,
            required_tool="curl",
        )
        body_result = self.runner.run(
            name=f"http_body_{prefix}",
            command=["curl", "-ksL", "--max-time", "12", endpoint.url],
            artifact_prefix=f"http_body_{prefix}",
            timeout=30,
            required_tool="curl",
        )
        summary.command_results.extend([header_result, body_result])
        endpoint.reachable = header_result.returncode == 0 or body_result.returncode == 0

        if header_result.stdout_path:
            header_text = Path(header_result.stdout_path).read_text(encoding="utf-8", errors="replace")
            server_match = re.search(r"^Server:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
            if server_match:
                endpoint.server_header = server_match.group(1).strip()
            status_match = re.search(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", header_text, re.MULTILINE)
            if status_match:
                endpoint.status_code = status_match.group(1)
                if endpoint.status_code.startswith("2"):
                    endpoint.notes.append("HTTP probe returned a 2xx response.")

            for header_name in COMMON_SECURITY_HEADERS:
                header_match = re.search(
                    rf"^{re.escape(header_name)}:\s*(.+)$",
                    header_text,
                    re.IGNORECASE | re.MULTILINE,
                )
                if header_match:
                    endpoint.security_headers[header_name] = header_match.group(1).strip()

        if body_result.stdout_path:
            body_text = Path(body_result.stdout_path).read_text(encoding="utf-8", errors="replace")
            title_match = re.search(r"<title>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
            if title_match:
                endpoint.title = re.sub(r"\s+", " ", title_match.group(1)).strip()
        if not endpoint.reachable:
            endpoint.notes.append("No successful HTTP response was captured during the probe window.")

        summary.http_endpoints.append(endpoint)

    def _probe_tls(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        if not endpoint.url.startswith("https://"):
            return

        prefix = slugify(endpoint.url)
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        host_port = f"{host}:{port}"
        result = self.runner.run(
            name=f"tls_probe_{prefix}",
            command=["openssl", "s_client", "-brief", "-connect", host_port, "-servername", host],
            artifact_prefix=f"tls_probe_{prefix}",
            timeout=30,
            required_tool="openssl",
        )
        summary.command_results.append(result)

    def _probe_whatweb(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        prefix = slugify(endpoint.url)
        result = self.runner.run(
            name=f"whatweb_{prefix}",
            command=["whatweb", "--no-errors", endpoint.url],
            artifact_prefix=f"whatweb_{prefix}",
            timeout=60,
            required_tool="whatweb",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            whatweb_text = Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").strip()
            if whatweb_text:
                endpoint.technologies.append(whatweb_text.splitlines()[0][:180])
                endpoint.notes.append("Technology fingerprint collected.")


class WebScanner:
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.runner = CommandRunner(session_dir)
        self._target_scanner = TargetScanner(session_dir)

    def scan(self, raw_url: str, profile: str = "standard") -> TargetSummary:
        if profile not in WEB_AUTOMATION_PROFILES:
            raise ValueError(f"Unsupported web profile '{profile}'. Choose one of: {', '.join(WEB_AUTOMATION_PROFILES)}")

        target = normalize_url(raw_url)
        summary = TargetSummary(
            target=target["url"],
            target_kind="url",
            session_id=self.session_dir.name,
            profile=f"web-{profile}",
            started_at=now_iso(),
            output_dir=str(self.session_dir),
            web_observations={
                "profile": profile,
                "host": target["host"],
                "scheme": target["scheme"],
                "interesting_urls": [],
                "related_hosts": [],
                "content_types": [],
                "waf": "",
                "crawl_url_count": 0,
                "crawl_sample": [],
                "path_hits": [],
                "testssl_highlights": [],
                "tool_notes": [],
            },
        )

        summary.open_services.append(
            ServiceFinding(
                port=target["port"],
                protocol="tcp",
                service=target["scheme"],
                product="web",
                extra_info=target["host"],
            )
        )

        endpoint = HttpEndpoint(url=target["url"])
        self._target_scanner._probe_http_endpoint(endpoint, summary)
        self._target_scanner._probe_tls(endpoint, summary)
        self._target_scanner._probe_whatweb(endpoint, summary)
        self._probe_httpx(endpoint, summary)
        self._probe_known_paths(endpoint, summary)

        if profile in {"standard", "deep"}:
            self._probe_wafw00f(endpoint, summary)
            self._probe_katana(endpoint, summary, deep=profile == "deep")

        if profile == "deep":
            self._probe_testssl(endpoint, summary)

        summary.recommended_steps = self._recommended_steps(summary)
        summary.findings = FindingsAnalyzer.generate(summary)
        return summary

    def _probe_httpx(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        prefix = slugify(endpoint.url)
        result = self.runner.run(
            name=f"httpx_{prefix}",
            command=[
                "httpx",
                "-u",
                endpoint.url,
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-follow-host-redirects",
            ],
            artifact_prefix=f"httpx_{prefix}",
            timeout=90,
            required_tool="httpx",
        )
        summary.command_results.append(result)
        if not result.stdout_path or not Path(result.stdout_path).exists():
            return

        lines = [
            line.strip()
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        if not lines:
            return

        try:
            payload = json.loads(lines[0])
        except json.JSONDecodeError:
            return

        endpoint.reachable = endpoint.reachable or bool(payload.get("status_code"))
        endpoint.status_code = endpoint.status_code or str(payload.get("status_code", "") or "")
        endpoint.title = endpoint.title or str(payload.get("title", "") or "")
        endpoint.server_header = endpoint.server_header or str(payload.get("webserver", "") or payload.get("server", "") or "")

        technologies = payload.get("tech") or payload.get("technologies") or []
        if isinstance(technologies, str):
            technologies = [technologies]
        append_unique(endpoint.technologies, *(str(item) for item in technologies))

        location = str(payload.get("location", "") or "")
        if location:
            endpoint.notes.append(f"Redirect/location observed: {location}")
            append_unique(summary.web_observations["interesting_urls"], location)

        content_type = str(payload.get("content_type", "") or "")
        if content_type:
            append_unique(summary.web_observations["content_types"], content_type)

        host_ip = payload.get("host") or payload.get("ip")
        if host_ip:
            summary.web_observations["resolved_host"] = host_ip

        cname = payload.get("cname")
        if isinstance(cname, list):
            append_unique(summary.web_observations["related_hosts"], *(str(item) for item in cname))
        elif cname:
            append_unique(summary.web_observations["related_hosts"], str(cname))

        cdn = str(payload.get("cdn", "") or "")
        if cdn:
            summary.web_observations["cdn"] = cdn

        url_value = str(payload.get("url", "") or "")
        if url_value:
            append_unique(summary.web_observations["interesting_urls"], url_value)

    def _probe_known_paths(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        base = endpoint.url.rstrip("/")
        for path in KNOWN_WEB_PATHS:
            url = f"{base}{path}"
            prefix = slugify(url)
            result = self.runner.run(
                name=f"known_path_{prefix}",
                command=["curl", "-ksS", "-L", "--max-time", "12", "-o", "-", "-D", "-", url],
                artifact_prefix=f"known_path_{prefix}",
                timeout=25,
                required_tool="curl",
            )
            summary.command_results.append(result)
            if result.returncode != 0 or not result.stdout_path:
                continue

            content = Path(result.stdout_path).read_text(encoding="utf-8", errors="replace")
            status_match = re.search(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", content, re.MULTILINE)
            if not status_match or not status_match.group(1).startswith(("2", "3")):
                continue

            append_unique(summary.web_observations["path_hits"], path)
            append_unique(summary.web_observations["interesting_urls"], url)

    def _probe_wafw00f(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        prefix = slugify(endpoint.url)
        result = self.runner.run(
            name=f"wafw00f_{prefix}",
            command=["wafw00f", endpoint.url, "-a"],
            artifact_prefix=f"wafw00f_{prefix}",
            timeout=90,
            required_tool="wafw00f",
        )
        summary.command_results.append(result)
        if not result.stdout_path or not Path(result.stdout_path).exists():
            return

        output = Path(result.stdout_path).read_text(encoding="utf-8", errors="replace")
        match = re.search(r"behind (.+?) WAF", output, re.IGNORECASE)
        if match:
            summary.web_observations["waf"] = match.group(1).strip()
        elif re.search(r"No WAF", output, re.IGNORECASE):
            summary.web_observations["tool_notes"].append("wafw00f did not identify a WAF.")

    def _probe_katana(self, endpoint: HttpEndpoint, summary: TargetSummary, deep: bool = False) -> None:
        prefix = slugify(endpoint.url)
        depth = "5" if deep else "3"
        duration = "4m" if deep else "2m"
        result = self.runner.run(
            name=f"katana_{prefix}",
            command=[
                "katana",
                "-u",
                endpoint.url,
                "-d",
                depth,
                "-jc",
                "-kf",
                "robotstxt,sitemapxml",
                "-iqp",
                "-j",
                "-ct",
                duration,
            ],
            artifact_prefix=f"katana_{prefix}",
            timeout=360 if deep else 180,
            required_tool="katana",
        )
        summary.command_results.append(result)
        if not result.stdout_path or not Path(result.stdout_path).exists():
            return

        discovered: List[str] = []
        for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            request_data = payload.get("request") or {}
            candidate = (
                payload.get("url")
                or request_data.get("endpoint")
                or request_data.get("url")
                or ""
            )
            if candidate:
                append_unique(discovered, str(candidate))

        summary.web_observations["crawl_url_count"] = len(discovered)
        summary.web_observations["crawl_sample"] = discovered[:25]
        append_unique(summary.web_observations["interesting_urls"], *discovered[:50])

    def _probe_testssl(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        if not endpoint.url.startswith("https://"):
            return

        prefix = slugify(endpoint.url)
        result = self.runner.run(
            name=f"testssl_{prefix}",
            command=["testssl.sh", endpoint.url],
            artifact_prefix=f"testssl_{prefix}",
            timeout=420,
            required_tool="testssl.sh",
        )
        summary.command_results.append(result)
        if not result.stdout_path or not Path(result.stdout_path).exists():
            return

        highlights: List[str] = []
        for raw_line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            lower = line.lower()
            if not line:
                continue
            if any(marker in lower for marker in [" hsts ", "ocsp", "certificate", "tls", "cipher", "protocol"]):
                append_unique(highlights, line[:200])
            if len(highlights) >= 8:
                break
        summary.web_observations["testssl_highlights"] = highlights

    def _recommended_steps(self, summary: TargetSummary) -> List[str]:
        steps: List[str] = []
        observations = summary.web_observations
        if observations.get("waf"):
            steps.append("Account for the identified WAF/WAAP before planning deeper validation or rate-heavy workflows.")
        if observations.get("crawl_url_count", 0) > 20:
            steps.append("Review the crawl sample and group endpoints by auth, admin, API, and static asset patterns.")
        if any(url.lower().endswith(("openapi.json", "swagger.json")) for url in observations.get("interesting_urls", [])):
            steps.append("The target appears to expose API documentation. Consider an API-specific review flow next.")
        if any("graphql" in url.lower() for url in observations.get("interesting_urls", [])):
            steps.append("GraphQL-style routes were observed. Confirm schema exposure and auth behavior manually.")
        if any(path in observations.get("path_hits", []) for path in ["/robots.txt", "/sitemap.xml"]):
            steps.append("Use robots.txt and sitemap.xml as seeds for manual review and coverage validation.")
        if not steps:
            steps.append("Review the collected headers, technologies, and crawl output to choose the next scoped web checks.")
        return steps


class ConsoleUI:
    _boot_seen = False
    _rich_console = Console() if RICH_AVAILABLE else None

    @staticmethod
    def supports_animation() -> bool:
        return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"

    @staticmethod
    def use_rich() -> bool:
        return RICH_AVAILABLE and ConsoleUI._rich_console is not None and sys.stdout.isatty()

    @staticmethod
    def _terminal_width() -> int:
        return max(72, shutil.get_terminal_size((120, 40)).columns)

    @staticmethod
    def _rule(char: str = "-") -> str:
        return char * min(ConsoleUI._terminal_width(), 104)

    @staticmethod
    def _matrix_line(width: int) -> str:
        chunks: List[str] = []
        while len(" ".join(chunks)) < width:
            token_len = random.randint(3, 10)
            chunks.append("".join(random.choice(MATRIX_GLYPHS) for _ in range(token_len)))
        return " ".join(chunks)[:width]

    @staticmethod
    def _print_logo_block() -> None:
        width = ConsoleUI._terminal_width()
        logo = [
            "  ______    ___    _______    ______    ______    ____   ____ ",
            " |_  _  | .'   `. |_   __ \\ .' ____ \\ .' ____ \\  |_  _| |_  _|",
            "   \\ \\  / /  .-.  \\  | |__) / | (___ \\_| (___ \\_|   \\ \\   / /  ",
            "    > `' <| |   | |  |  __ / '.___`-.  '.___`-.     \\ \\ / /   ",
            "  _/ /'`\\ \\\\  `-'  / _| |  \\ \\|`\\____) ||`\\____) |    \\ ' /    ",
            " |____||____|`.___.' |____| |___|______.'|______.'      \\_/     ",
        ]
        print(f"{Colors.CYAN}{ConsoleUI._rule('=')}{Colors.RESET}")
        for line in logo:
            print(f"{Colors.CYAN}{line.center(width)}{Colors.RESET}")
        print(
            f"{Colors.YELLOW}"
            f"{'Operator Workbench for Host, Web, Evidence, and Reporting Pipelines'.center(width)}"
            f"{Colors.RESET}"
        )
        print(f"{Colors.CYAN}{ConsoleUI._rule('=')}{Colors.RESET}")

    @staticmethod
    def _print_rich_logo() -> None:
        if not ConsoleUI.use_rich():
            ConsoleUI._print_logo_block()
            return
        logo_text = "\n".join(
            [
                "  ______    ___    _______    ______    ______    ____   ____ ",
                " |_  _  | .'   `. |_   __ \\ .' ____ \\ .' ____ \\  |_  _| |_  _|",
                "   \\ \\  / /  .-.  \\  | |__) / | (___ \\_| (___ \\_|   \\ \\   / /  ",
                "    > `' <| |   | |  |  __ / '.___`-.  '.___`-.     \\ \\ / /   ",
                "  _/ /'`\\ \\\\  `-'  / _| |  \\ \\|`\\____) ||`\\____) |    \\ ' /    ",
                " |____||____|`.___.' |____| |___|______.'|______.'      \\_/     ",
            ]
        )
        ConsoleUI._rich_console.print(
            Panel.fit(
                f"[bold cyan]{logo_text}[/bold cyan]\n[bold yellow]Operator Workbench for Host, Web, Evidence, and Reporting Pipelines[/bold yellow]",
                border_style="bright_cyan",
                padding=(1, 2),
                title="[bold green]ZACAIM[/bold green]",
                subtitle="[cyan]live interface[/cyan]",
            )
        )

    @staticmethod
    def _rich_card(title: str, body_lines: List[str], style: str = "cyan") -> Any:
        content = "\n".join(body_lines)
        return Panel(content, title=f"[bold]{title}[/bold]", border_style=style, padding=(1, 2))

    @staticmethod
    def _prompt_label() -> str:
        return f"{Colors.GREEN}zacaim{Colors.RESET}{Colors.CYAN}::ops{Colors.RESET}> "

    @staticmethod
    def banner() -> None:
        if ConsoleUI.use_rich():
            ConsoleUI._print_rich_logo()
            return
        ConsoleUI._print_logo_block()

    @classmethod
    def boot_sequence(cls) -> None:
        if cls._boot_seen:
            return
        cls._boot_seen = True
        clear_screen()

        if not cls.supports_animation():
            cls.banner()
            return

        width = min(cls._terminal_width(), 104)
        print(f"{Colors.GREEN}{cls._rule('~')}{Colors.RESET}")
        for _ in range(10):
            left = cls._matrix_line(max(24, width // 2 - 5))
            right = " ".join(random.choice(BOOT_TOKENS) for _ in range(4))
            print(f"{Colors.GREEN}{left:<{max(24, width // 2)}}{Colors.RESET} {Colors.CYAN}{right}{Colors.RESET}")
            time.sleep(0.035)

        print(f"{Colors.GREEN}{cls._rule('~')}{Colors.RESET}")
        print(f"{Colors.BLUE}[ matrix ]{Colors.RESET} synthesizing interface layers")
        for label, text in BOOT_STATUS_LINES:
            for frame in LIVE_FRAMES[:4]:
                pulse = "".join(random.choice("01") for _ in range(18))
                sys.stdout.write(
                    f"\r{Colors.GREEN}{pulse}{Colors.RESET} "
                    f"{Colors.CYAN}{frame}{Colors.RESET} "
                    f"{Colors.BOLD}{label:<6}{Colors.RESET} {text:<36}"
                )
                sys.stdout.flush()
                time.sleep(0.07)
            sys.stdout.write(
                f"\r{Colors.GREEN}[ synced ]{Colors.RESET} {Colors.BOLD}{label:<6}{Colors.RESET} {text:<36}\n"
            )
            sys.stdout.flush()

        time.sleep(0.2)
        clear_screen()
        cls.banner()

    @staticmethod
    def section(title: str) -> None:
        if ConsoleUI.use_rich():
            ConsoleUI._rich_console.print(Rule(f"[bold magenta]{title.upper()}[/bold magenta]", style="magenta"))
            return
        width = min(ConsoleUI._terminal_width(), 104)
        right = "-" * max(4, width - len(title) - 8)
        print(f"{Colors.MAGENTA}{Colors.BOLD}-- {title.upper()} {right}{Colors.RESET}")

    @staticmethod
    def _tool_state_label(location: str) -> str:
        return f"{Colors.GREEN}online{Colors.RESET}" if location else f"{Colors.RED}missing{Colors.RESET}"

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "critical": Colors.RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.CYAN,
            "info": Colors.BLUE,
        }.get(severity.lower(), Colors.RESET)

    @staticmethod
    def health_view(payload: Dict[str, Any]) -> None:
        if ConsoleUI.use_rich():
            env = Table(box=None, expand=True, show_header=False)
            env.add_column("key", style="cyan", width=14)
            env.add_column("value", style="white")
            env.add_row("Python", payload["python"])
            env.add_row("Hostname", payload["hostname"])
            env.add_row("Sessions", payload["sessions_dir"])
            env.add_row("Engagements", payload["engagements_dir"])
            env.add_row("Root", str(payload["root"]))

            tools = Table(title="Tool Readiness", expand=True)
            tools.add_column("Tool", style="bold cyan")
            tools.add_column("State")
            tools.add_column("Location", overflow="fold")
            for tool, location in payload["tools"].items():
                state = "[green]online[/green]" if location else "[red]missing[/red]"
                tools.add_row(tool, state, location or "-")

            ConsoleUI._rich_console.print(Panel(env, title="[bold]Environment[/bold]", border_style="magenta"))
            ConsoleUI._rich_console.print(tools)
            return
        ConsoleUI.section("Environment")
        print(f"{Colors.BLUE}Python:{Colors.RESET} {payload['python']}")
        print(f"{Colors.BLUE}Hostname:{Colors.RESET} {payload['hostname']}")
        print(f"{Colors.BLUE}Sessions:{Colors.RESET} {payload['sessions_dir']}")
        print(f"{Colors.BLUE}Engagements:{Colors.RESET} {payload['engagements_dir']}")
        print(f"{Colors.BLUE}Root:{Colors.RESET} {payload['root']}")
        print(f"{Colors.BLUE}Tools:{Colors.RESET}")
        for tool, location in payload["tools"].items():
            state = location if location else "missing"
            color = Colors.GREEN if location else Colors.RED
            print(f"  - {tool:<8} {color}{state}{Colors.RESET}")

    @staticmethod
    def dashboard(manager: "EngagementManager") -> None:
        engagements = manager.list_engagements()
        sessions_count = len(list(SESSIONS_DIR.iterdir())) if SESSIONS_DIR.exists() else 0
        config = read_json(CONFIG_FILE, {})
        available_tools = sum(1 for location in config.get("tools", {}).values() if location)
        total_tools = len(config.get("tools", {}))

        if ConsoleUI.use_rich():
            cards = [
                ConsoleUI._rich_card(
                    "Workspace",
                    [
                        f"[bold cyan]engagements[/bold cyan]  {len(engagements)}",
                        f"[bold cyan]sessions[/bold cyan]     {sessions_count}",
                        f"[bold cyan]tools-ready[/bold cyan] {available_tools}/{total_tools or len(HealthChecker.REQUIRED_TOOLS) + len(HealthChecker.OPTIONAL_TOOLS)}",
                    ],
                    "cyan",
                ),
                ConsoleUI._rich_card(
                    "Live Channel",
                    [
                        "[green]operator console online[/green]",
                        f"[yellow]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]",
                        "[cyan]mode[/cyan] interactive workstation",
                    ],
                    "green",
                ),
                ConsoleUI._rich_card(
                    "Pipelines",
                    [
                        "[cyan]host[/cyan] multi-tool enrichment",
                        "[cyan]web[/cyan] deep automation profiles",
                        "[cyan]evidence[/cyan] sessions, notes, reports",
                    ],
                    "magenta",
                ),
            ]
            ConsoleUI._rich_console.print(Columns(cards, expand=True))
            return

        ConsoleUI.section("Workspace")
        width = min(ConsoleUI._terminal_width(), 104)
        box_width = width - 2
        metrics = (
            f"engagements={len(engagements)}   "
            f"sessions={sessions_count}   "
            f"tools-ready={available_tools}/{total_tools or len(HealthChecker.REQUIRED_TOOLS) + len(HealthChecker.OPTIONAL_TOOLS)}"
        )
        live_line = (
            f"{Colors.GREEN}live-channel online{Colors.RESET}   "
            f"{Colors.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}"
        )
        print(f"{Colors.BLUE}+{'-' * box_width}+{Colors.RESET}")
        print(f"{Colors.BLUE}|{Colors.RESET} {metrics:<{box_width - 2}} {Colors.BLUE}|{Colors.RESET}")
        print(f"{Colors.BLUE}|{Colors.RESET} {live_line:<{box_width - 2}} {Colors.BLUE}|{Colors.RESET}")
        print(f"{Colors.BLUE}+{'-' * box_width}+{Colors.RESET}")

    @staticmethod
    def ready_pulse(cycles: int = 8) -> None:
        if not ConsoleUI.supports_animation():
            print(f"{Colors.GREEN}[live]{Colors.RESET} interface ready")
            return
        for index in range(cycles):
            frame = LIVE_FRAMES[index % len(LIVE_FRAMES)]
            sys.stdout.write(
                f"\r{Colors.GREEN}{''.join(random.choice('01') for _ in range(10))}{Colors.RESET} "
                f"{Colors.CYAN}{frame}{Colors.RESET} interface ready, waiting for operator input"
            )
            sys.stdout.flush()
            time.sleep(0.08)
        sys.stdout.write("\r" + (" " * 96) + "\r")
        sys.stdout.flush()
        print(f"{Colors.GREEN}[live]{Colors.RESET} interface ready, waiting for operator input")

    @staticmethod
    def print_engagements(engagements: List[Dict[str, Any]]) -> None:
        if ConsoleUI.use_rich():
            if not engagements:
                ConsoleUI._rich_console.print(Panel("No engagements registered yet.\nRun [bold]engagement init[/bold] to start a workspace.", border_style="yellow"))
                return
            table = Table(title="Engagements", expand=True)
            table.add_column("ID", style="bold cyan")
            table.add_column("Name", style="white")
            table.add_column("Created", style="green")
            table.add_column("Scope", style="yellow")
            for engagement in engagements:
                table.add_row(
                    engagement["id"],
                    engagement["name"],
                    engagement.get("created_at", "n/a"),
                    engagement.get("scope", "") or "n/a",
                )
            ConsoleUI._rich_console.print(table)
            return
        ConsoleUI.section("Engagements")
        if not engagements:
            print("No engagements registered yet.")
            return
        for engagement in engagements:
            print(
                f"- {engagement['id']} | {engagement['name']} | "
                f"created={engagement.get('created_at', 'n/a')} | "
                f"scope={engagement.get('scope', '') or 'n/a'}"
            )

    @staticmethod
    def print_targets(targets: List[Dict[str, Any]]) -> None:
        if ConsoleUI.use_rich():
            if not targets:
                ConsoleUI._rich_console.print(Panel("No targets registered.\nAdd a target to enrich the workspace.", border_style="yellow"))
                return
            table = Table(title="Targets", expand=True)
            table.add_column("Target", style="bold cyan")
            table.add_column("Address", style="white")
            table.add_column("Services", justify="right")
            table.add_column("Findings", justify="right")
            table.add_column("Notes", justify="right")
            table.add_column("Evidence", justify="right")
            for target in targets:
                table.add_row(
                    target["target_id"],
                    target["address"],
                    str(target["service_count"]),
                    str(target["findings_count"]),
                    str(target["note_count"]),
                    str(target["evidence_count"]),
                )
            ConsoleUI._rich_console.print(table)
            return
        ConsoleUI.section("Targets")
        if not targets:
            print("No targets registered.")
            return
        for target in targets:
            print(
                f"- {target['target_id']} | {target['address']} | "
                f"services={target['service_count']} | findings={target['findings_count']} | "
                f"notes={target['note_count']} | evidence={target['evidence_count']}"
            )

    @staticmethod
    def print_record(title: str, payload: Dict[str, Any]) -> None:
        if ConsoleUI.use_rich():
            table = Table(box=None, show_header=False, expand=True)
            table.add_column("key", style="bold cyan", width=18)
            table.add_column("value", style="white", overflow="fold")
            for key, value in payload.items():
                table.add_row(str(key), str(value))
            ConsoleUI._rich_console.print(Panel(table, title=f"[bold]{title}[/bold]", border_style="magenta"))
            return
        ConsoleUI.section(title)
        for key, value in payload.items():
            print(f"- {key}: {value}")

    @staticmethod
    def print_wifi_status(payload: Dict[str, Any]) -> None:
        if ConsoleUI.use_rich():
            table = Table(title="WiFi Status", expand=True)
            table.add_column("Type", style="bold cyan")
            table.add_column("Name", style="white")
            table.add_column("Detail", style="yellow", overflow="fold")
            for tool, location in payload["tools"].items():
                state = "online" if location else "missing"
                table.add_row("tool", tool, f"{state} {location or ''}".strip())
            for interface in payload["interfaces"]:
                table.add_row(
                    "iface",
                    interface.get("name", "unknown"),
                    f"type={interface.get('type', 'n/a')} channel={interface.get('channel', 'n/a')} state={interface.get('state', 'n/a')}",
                )
            ConsoleUI._rich_console.print(table)
            ConsoleUI._rich_console.print(Panel(payload["note"], border_style="blue", title="Note"))
            return
        ConsoleUI.section("WiFi Status")
        for tool, location in payload["tools"].items():
            state = ConsoleUI._tool_state_label(location)
            print(f"- tool {tool}: {state} {location or ''}".rstrip())
        if payload["interfaces"]:
            for interface in payload["interfaces"]:
                print(
                    f"- iface {interface.get('name', 'unknown')} | "
                    f"type={interface.get('type', 'n/a')} | "
                    f"channel={interface.get('channel', 'n/a')} | "
                    f"state={interface.get('state', 'n/a')}"
                )
        else:
            print("- No wireless interfaces were detected by the local status check.")
        print(f"- note: {payload['note']}")

    @staticmethod
    def print_scan_report(output: Dict[str, str]) -> None:
        summary = read_json(Path(output["summary_json"]), {})
        findings = read_json(Path(output["findings_json"]), [])
        if not summary:
            print(json.dumps(output, indent=2))
            return

        if ConsoleUI.use_rich():
            meta = Table(box=None, show_header=False, expand=True)
            meta.add_column("key", style="bold cyan", width=12)
            meta.add_column("value", style="white", overflow="fold")
            meta.add_row("Target", str(summary.get("target", "n/a")))
            meta.add_row("Profile", str(summary.get("profile", "n/a")))
            meta.add_row("Session", str(summary.get("session_id", "n/a")))
            meta.add_row("Output", str(summary.get("output_dir", "n/a")))
            ConsoleUI._rich_console.print(Panel(meta, title="[bold]Scan Summary[/bold]", border_style="cyan"))

            services = summary.get("open_services", [])
            if services:
                service_table = Table(title="Service Matrix", expand=True)
                service_table.add_column("Port", style="bold cyan", justify="right")
                service_table.add_column("Proto", style="cyan")
                service_table.add_column("Service", style="white")
                service_table.add_column("Product", style="yellow")
                service_table.add_column("Version", style="green")
                for service in services:
                    service_table.add_row(
                        str(service.get("port", "n/a")),
                        str(service.get("protocol", "tcp")),
                        str(service.get("service", "unknown")),
                        str(service.get("product", "") or "-"),
                        str(service.get("version", "") or "-"),
                    )
                ConsoleUI._rich_console.print(service_table)
            else:
                ConsoleUI._rich_console.print(Panel("No services were parsed.", title="Service Matrix", border_style="yellow"))

            panels: List[Any] = []
            host_observations = summary.get("host_observations", {})
            if host_observations:
                host_lines = []
                groups = host_observations.get("service_groups", {})
                if groups:
                    host_lines.append(" | ".join(f"{name}={count}" for name, count in groups.items()))
                if host_observations.get("reverse_dns"):
                    host_lines.append("reverse-dns: " + ", ".join(host_observations["reverse_dns"]))
                for line in host_observations.get("ssh_host_keys", [])[:4]:
                    host_lines.append("ssh: " + line)
                for line in host_observations.get("tls_highlights", [])[:4]:
                    host_lines.append("tls: " + line)
                if host_lines:
                    panels.append(ConsoleUI._rich_card("Host Automation", host_lines, "magenta"))

            web_lines = []
            endpoints = summary.get("http_endpoints", [])
            for endpoint in endpoints[:6]:
                web_lines.append(
                    f"{endpoint.get('url', 'n/a')}\nstatus={endpoint.get('status_code', 'n/a')} title={endpoint.get('title', 'n/a') or 'n/a'}"
                )
            web_observations = summary.get("web_observations", {})
            if web_observations:
                web_lines.append(
                    f"profile={web_observations.get('profile', 'n/a')} crawl_urls={web_observations.get('crawl_url_count', 0)} waf={web_observations.get('waf') or 'n/a'}"
                )
                if web_observations.get("path_hits"):
                    web_lines.append("known-paths: " + ", ".join(web_observations["path_hits"]))
            if web_lines:
                panels.append(ConsoleUI._rich_card("Web Automation", web_lines, "cyan"))

            recommended_steps = summary.get("recommended_steps", [])
            if recommended_steps:
                panels.append(ConsoleUI._rich_card("Next Steps", [f"- {step}" for step in recommended_steps], "green"))

            if panels:
                ConsoleUI._rich_console.print(Columns(panels, expand=True))

            if findings:
                finding_table = Table(title="Findings", expand=True)
                finding_table.add_column("Severity", style="bold")
                finding_table.add_column("Title", style="white")
                finding_table.add_column("Description", style="yellow", overflow="fold")
                for finding in findings:
                    severity = str(finding.get("severity", "info")).upper()
                    sev_style = {
                        "CRITICAL": "bold red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "cyan",
                        "INFO": "blue",
                    }.get(severity, "white")
                    finding_table.add_row(f"[{sev_style}]{severity}[/{sev_style}]", str(finding.get("title", "Untitled")), str(finding.get("description", "")))
                ConsoleUI._rich_console.print(finding_table)
            else:
                ConsoleUI._rich_console.print(Panel("No structured findings were generated.", title="Findings", border_style="yellow"))

            artifact_table = Table(title="Artifacts", expand=True, box=None)
            artifact_table.add_column("Type", style="bold cyan", width=10)
            artifact_table.add_column("Path", style="white", overflow="fold")
            artifact_table.add_row("summary", output["summary_json"])
            artifact_table.add_row("findings", output["findings_json"])
            artifact_table.add_row("report", output["report_md"])
            ConsoleUI._rich_console.print(artifact_table)
            return

        ConsoleUI.section("Scan Summary")
        print(
            f"{Colors.BLUE}Target:{Colors.RESET} {summary.get('target', 'n/a')}   "
            f"{Colors.BLUE}Profile:{Colors.RESET} {summary.get('profile', 'n/a')}   "
            f"{Colors.BLUE}Session:{Colors.RESET} {summary.get('session_id', 'n/a')}"
        )
        print(f"{Colors.BLUE}Output:{Colors.RESET} {summary.get('output_dir', 'n/a')}")

        ConsoleUI.section("Services")
        services = summary.get("open_services", [])
        if services:
            for service in services:
                detail = " ".join(
                    part for part in [service.get("service", ""), service.get("product", ""), service.get("version", "")]
                    if part
                ).strip()
                print(f"- {service.get('port', 'n/a')}/{service.get('protocol', 'tcp')} | {detail or 'unknown'}")
        else:
            print("- No services were parsed.")

        host_observations = summary.get("host_observations", {})
        if host_observations:
            ConsoleUI.section("Host Automation")
            groups = host_observations.get("service_groups", {})
            if groups:
                print("- " + " | ".join(f"{name}={count}" for name, count in groups.items()))
            if host_observations.get("reverse_dns"):
                print(f"- reverse-dns={', '.join(host_observations['reverse_dns'])}")
            if host_observations.get("ssh_host_keys"):
                for line in host_observations["ssh_host_keys"][:4]:
                    print(f"- ssh {line}")
            if host_observations.get("tls_highlights"):
                for line in host_observations["tls_highlights"][:4]:
                    print(f"- tls {line}")

        ConsoleUI.section("Web")
        endpoints = summary.get("http_endpoints", [])
        if endpoints:
            for endpoint in endpoints:
                tech = ", ".join(endpoint.get("technologies", [])) or "n/a"
                print(
                    f"- {endpoint.get('url', 'n/a')} | status={endpoint.get('status_code', 'n/a')} | "
                    f"title={endpoint.get('title', 'n/a') or 'n/a'} | server={endpoint.get('server_header', 'n/a') or 'n/a'}"
                )
                print(f"  tech={tech}")
        else:
            print("- No HTTP/S endpoints were identified.")

        web_observations = summary.get("web_observations", {})
        if web_observations:
            ConsoleUI.section("Web Automation")
            print(
                f"- profile={web_observations.get('profile', 'n/a')} | "
                f"crawl_urls={web_observations.get('crawl_url_count', 0)} | "
                f"waf={web_observations.get('waf') or 'n/a'} | "
                f"cdn={web_observations.get('cdn') or 'n/a'}"
            )
            if web_observations.get("path_hits"):
                print(f"- known-paths={', '.join(web_observations['path_hits'])}")
            if web_observations.get("crawl_sample"):
                for url in web_observations["crawl_sample"][:8]:
                    print(f"- crawl {url}")
            if web_observations.get("testssl_highlights"):
                for line in web_observations["testssl_highlights"][:4]:
                    print(f"- tls {line}")

        ConsoleUI.section("Findings")
        if findings:
            for finding in findings:
                severity = finding.get("severity", "info")
                color = ConsoleUI._severity_color(severity)
                print(
                    f"- {color}[{severity.upper()}]{Colors.RESET} "
                    f"{finding.get('title', 'Untitled')}: {finding.get('description', '')}"
                )
        else:
            print("- No structured findings were generated.")

        ConsoleUI.section("Artifacts")
        print(f"- summary: {output['summary_json']}")
        print(f"- findings: {output['findings_json']}")
        print(f"- report: {output['report_md']}")

        recommended_steps = summary.get("recommended_steps", [])
        if recommended_steps:
            ConsoleUI.section("Next Steps")
            for step in recommended_steps:
                print(f"- {step}")

    @staticmethod
    def print_scan_reports(outputs: List[Dict[str, str]]) -> None:
        for index, output in enumerate(outputs, start=1):
            if len(outputs) > 1:
                if ConsoleUI.use_rich():
                    ConsoleUI._rich_console.print(Rule(f"[bold cyan]Result {index}/{len(outputs)}[/bold cyan]"))
                else:
                    print(f"{Colors.BOLD}Result {index}/{len(outputs)}{Colors.RESET}")
            ConsoleUI.print_scan_report(output)

    @staticmethod
    def prompt_main() -> str:
        if ConsoleUI.use_rich():
            cards = [
                ConsoleUI._rich_card("1  Health Check", ["verify toolchain", "inspect runtime paths"], "green"),
                ConsoleUI._rich_card("2  Web Automation", ["safe / standard / deep", "fingerprint + crawl + tls"], "cyan"),
                ConsoleUI._rich_card("3  Host Scan", ["service mapping", "host enrichment"], "magenta"),
                ConsoleUI._rich_card("4  Engagement Init", ["create workspace", "set scope and notes"], "yellow"),
                ConsoleUI._rich_card("5  Engagement Views", ["list engagements", "list targets"], "blue"),
                ConsoleUI._rich_card("6  Target Registry", ["add target", "scan one or many"], "cyan"),
                ConsoleUI._rich_card("9  Notes", ["attach notes", "tag observations"], "green"),
                ConsoleUI._rich_card("10 Evidence", ["store text", "copy files"], "magenta"),
                ConsoleUI._rich_card("11 WiFi Status", ["adapter readiness", "local wireless view"], "yellow"),
                ConsoleUI._rich_card("12 Exit", ["close operator console"], "red"),
            ]
            ConsoleUI._rich_console.print(Columns(cards, equal=True, expand=True))
            ConsoleUI._rich_console.print("[dim]Choices 7 and 8 are target listing and engagement scan flows.[/dim]")
            return input(f"\n{ConsoleUI._prompt_label()}").strip()
        print("1. Health Check")
        print("2. Web URL Scan")
        print("3. Standalone Host Scan")
        print("4. Create Engagement")
        print("5. List Engagements")
        print("6. Add Target To Engagement")
        print("7. List Engagement Targets")
        print("8. Scan Engagement Target(s)")
        print("9. Add Note")
        print("10. Add Evidence")
        print("11. WiFi Status")
        print("12. Exit")
        return input(f"\n{ConsoleUI._prompt_label()}").strip()


def run_health_check() -> Dict[str, Any]:
    payload = HealthChecker.run()
    ConsoleUI.health_view(payload)
    return payload


def run_standalone_scan(target: str, profile: str) -> Dict[str, str]:
    if profile not in DEFAULT_PROFILES:
        raise ValueError(f"Unsupported profile '{profile}'. Choose one of: {', '.join(DEFAULT_PROFILES)}")

    ensure_app_dirs()
    session_dir = WorkspaceManager().create_session(target, profile)
    scanner = TargetScanner(session_dir)
    summary = scanner.scan(target, profile)
    return {"session_dir": str(session_dir), **ReportBuilder.build(summary, session_dir)}


def run_web_scan(url: str, profile: str = "standard") -> Dict[str, str]:
    ensure_app_dirs()
    normalized = normalize_url(url)
    session_dir = WorkspaceManager().create_session(normalized["host"], f"web_{profile}")
    scanner = WebScanner(session_dir)
    summary = scanner.scan(url, profile=profile)
    return {"session_dir": str(session_dir), **ReportBuilder.build(summary, session_dir)}


def run_engagement_scan(
    engagement_id: str,
    profile: str,
    target_ref: str = "",
    all_targets: bool = False,
) -> List[Dict[str, str]]:
    if profile not in DEFAULT_PROFILES:
        raise ValueError(f"Unsupported profile '{profile}'. Choose one of: {', '.join(DEFAULT_PROFILES)}")

    manager = EngagementManager()
    metadata = manager.load_metadata(engagement_id)
    targets = manager.load_targets(engagement_id)
    if target_ref:
        targets = [manager.resolve_target(engagement_id, target_ref)]
    elif not all_targets and targets:
        targets = [targets[0]]

    if not targets:
        raise ValueError("No targets registered for this engagement.")

    engagement_dir = manager.get_engagement_dir(engagement_id)
    outputs: List[Dict[str, str]] = []
    for target in targets:
        session_dir = WorkspaceManager().create_session(
            target["address"],
            profile,
            sessions_root=engagement_dir / "sessions",
        )
        scanner = TargetScanner(session_dir)
        summary = scanner.scan(target["address"], profile)
        summary.engagement_id = metadata["id"]
        summary.target_label = target["name"]
        reports = ReportBuilder.build(summary, session_dir)
        manager.update_target_after_scan(engagement_id, target["target_id"], summary, reports)
        outputs.append(
            {
                "target_id": target["target_id"],
                "target": target["address"],
                "session_dir": str(session_dir),
                **reports,
            }
        )
    return outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=APP_NAME)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("health", help="Run dependency and environment checks.")

    scan_parser = subparsers.add_parser("scan", help="Run standalone target enumeration.")
    scan_parser.add_argument("target", help="Target IP address or hostname.")
    scan_parser.add_argument("--profile", choices=sorted(DEFAULT_PROFILES), default="standard")

    engagement_parser = subparsers.add_parser("engagement", help="Manage engagements and target registries.")
    engagement_subparsers = engagement_parser.add_subparsers(dest="engagement_command")

    engagement_init = engagement_subparsers.add_parser("init", help="Create a new engagement workspace.")
    engagement_init.add_argument("name", help="Display name for the engagement.")
    engagement_init.add_argument("--description", default="", help="Short description.")
    engagement_init.add_argument("--scope", default="", help="Authorized scope note.")

    engagement_subparsers.add_parser("list", help="List all engagements.")

    engagement_add_target = engagement_subparsers.add_parser("add-target", help="Register a target.")
    engagement_add_target.add_argument("engagement", help="Engagement id.")
    engagement_add_target.add_argument("target", help="Target IP address or hostname.")
    engagement_add_target.add_argument("--name", default="", help="Friendly target label.")
    engagement_add_target.add_argument("--tags", nargs="*", default=[], help="Optional tags.")

    engagement_list_targets = engagement_subparsers.add_parser("list-targets", help="List registered targets.")
    engagement_list_targets.add_argument("engagement", help="Engagement id.")

    engagement_scan = engagement_subparsers.add_parser("scan", help="Scan one or more registered targets.")
    engagement_scan.add_argument("engagement", help="Engagement id.")
    engagement_scan.add_argument("--target", default="", help="Target id, name, or address.")
    engagement_scan.add_argument("--all", action="store_true", help="Scan all registered targets.")
    engagement_scan.add_argument("--profile", choices=sorted(DEFAULT_PROFILES), default="standard")

    note_parser = subparsers.add_parser("note", help="Manage target notes.")
    note_subparsers = note_parser.add_subparsers(dest="note_command")
    note_add = note_subparsers.add_parser("add", help="Add a note to a target.")
    note_add.add_argument("engagement", help="Engagement id.")
    note_add.add_argument("target", help="Target id, name, or address.")
    note_add.add_argument("text", help="Note text.")
    note_add.add_argument("--category", default="note", help="Note category.")
    note_add.add_argument("--tags", nargs="*", default=[], help="Optional tags.")

    evidence_parser = subparsers.add_parser("evidence", help="Manage target evidence.")
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command")
    evidence_add = evidence_subparsers.add_parser("add", help="Add evidence to a target.")
    evidence_add.add_argument("engagement", help="Engagement id.")
    evidence_add.add_argument("target", help="Target id, name, or address.")
    evidence_group = evidence_add.add_mutually_exclusive_group(required=True)
    evidence_group.add_argument("--text", default="", help="Store evidence as text.")
    evidence_group.add_argument("--file", default="", help="Copy a file into the evidence store.")
    evidence_add.add_argument("--description", default="", help="Optional description.")

    web_parser = subparsers.add_parser("web", help="Authorized web automation and fingerprinting.")
    web_subparsers = web_parser.add_subparsers(dest="web_command")
    web_scan = web_subparsers.add_parser("scan", help="Run an authorized web discovery automation profile.")
    web_scan.add_argument("url", help="Target http/https URL.")
    web_scan.add_argument("--profile", choices=sorted(WEB_AUTOMATION_PROFILES), default="standard")

    wifi_parser = subparsers.add_parser("wifi", help="Inspect local wireless workspace readiness.")
    wifi_subparsers = wifi_parser.add_subparsers(dest="wifi_command")
    wifi_subparsers.add_parser("status", help="Show local wireless adapter and tool status.")

    return parser.parse_args()


def interactive_main() -> None:
    ensure_app_dirs()
    manager = EngagementManager()

    while True:
        ConsoleUI.boot_sequence()
        clear_screen()
        ConsoleUI.banner()
        ConsoleUI.dashboard(manager)
        ConsoleUI.ready_pulse()
        choice = ConsoleUI.prompt_main()

        try:
            if choice == "1":
                clear_screen()
                ConsoleUI.banner()
                with LiveStatus("running environment checks", "health check complete"):
                    payload = HealthChecker.run()
                ConsoleUI.health_view(payload)
            elif choice == "2":
                clear_screen()
                ConsoleUI.banner()
                url = input("Target URL: ").strip()
                profile = input("Web profile [standard]: ").strip().lower() or "standard"
                with LiveStatus("running web automation pipeline", "web automation complete"):
                    output = run_web_scan(url, profile=profile)
                ConsoleUI.print_scan_report(output)
            elif choice == "3":
                ConsoleUI.banner()
                target = input("Target IP/hostname: ").strip()
                profile = input("Profile [standard]: ").strip().lower() or "standard"
                with LiveStatus("running host scan", "host scan complete"):
                    output = run_standalone_scan(target, profile)
                ConsoleUI.print_scan_report(output)
            elif choice == "4":
                ConsoleUI.banner()
                name = input("Engagement name: ").strip()
                description = input("Description: ").strip()
                scope = input("Scope note: ").strip()
                ConsoleUI.print_record("Engagement Created", manager.create(name, description, scope))
            elif choice == "5":
                ConsoleUI.banner()
                ConsoleUI.print_engagements(manager.list_engagements())
            elif choice == "6":
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Target IP/hostname: ").strip()
                name = input("Friendly name (optional): ").strip()
                tags = input("Tags (space separated): ").strip().split()
                ConsoleUI.print_record("Target Added", manager.add_target(engagement, target, name, tags))
            elif choice == "7":
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                ConsoleUI.print_targets(manager.load_targets(engagement))
            elif choice == "8":
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Specific target id/name/address (blank for all): ").strip()
                profile = input("Profile [standard]: ").strip().lower() or "standard"
                with LiveStatus("running engagement scans", "engagement scans complete"):
                    outputs = run_engagement_scan(engagement, profile, target_ref=target, all_targets=not target)
                ConsoleUI.print_scan_reports(outputs)
            elif choice == "9":
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Target id/name/address: ").strip()
                category = input("Category [note]: ").strip() or "note"
                tags = input("Tags (space separated): ").strip().split()
                text = input("Note text: ").strip()
                ConsoleUI.print_record("Note Added", manager.add_note(engagement, target, text, category, tags))
            elif choice == "10":
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Target id/name/address: ").strip()
                description = input("Description: ").strip()
                text = input("Evidence text (leave blank to use file path): ").strip()
                if text:
                    result = manager.add_evidence(engagement, target, description=description, text=text)
                else:
                    file_path = input("Evidence file path: ").strip()
                    result = manager.add_evidence(engagement, target, description=description, file_path=file_path)
                ConsoleUI.print_record("Evidence Added", result)
            elif choice == "11":
                clear_screen()
                ConsoleUI.banner()
                with LiveStatus("collecting wireless adapter status", "wifi status ready"):
                    payload = WifiInspector.run()
                ConsoleUI.print_wifi_status(payload)
            elif choice == "12":
                print("Good hunting. Stay within scope.")
                return
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
        except Exception as exc:
            print(f"{Colors.RED}[!] {exc}{Colors.RESET}")

        input("\nPress Enter to continue...")


def main() -> None:
    args = parse_args()
    manager = EngagementManager()

    if args.command == "health":
        run_health_check()
        return

    if args.command == "scan":
        output = run_standalone_scan(args.target, args.profile)
        if sys.stdout.isatty():
            ConsoleUI.print_scan_report(output)
        else:
            print(json.dumps(output, indent=2))
        return

    if args.command == "web" and args.web_command == "scan":
        output = run_web_scan(args.url, profile=args.profile)
        if sys.stdout.isatty():
            ConsoleUI.print_scan_report(output)
        else:
            print(json.dumps(output, indent=2))
        return

    if args.command == "wifi" and args.wifi_command == "status":
        payload = WifiInspector.run()
        if sys.stdout.isatty():
            ConsoleUI.print_wifi_status(payload)
        else:
            print(json.dumps(payload, indent=2))
        return

    if args.command == "engagement":
        if args.engagement_command == "init":
            payload = manager.create(args.name, args.description, args.scope)
            if sys.stdout.isatty():
                ConsoleUI.print_record("Engagement Created", payload)
            else:
                print(json.dumps(payload, indent=2))
            return
        if args.engagement_command == "list":
            payload = manager.list_engagements()
            if sys.stdout.isatty():
                ConsoleUI.print_engagements(payload)
            else:
                print(json.dumps(payload, indent=2))
            return
        if args.engagement_command == "add-target":
            payload = manager.add_target(args.engagement, args.target, args.name, args.tags)
            if sys.stdout.isatty():
                ConsoleUI.print_record("Target Added", payload)
            else:
                print(json.dumps(payload, indent=2))
            return
        if args.engagement_command == "list-targets":
            payload = manager.load_targets(args.engagement)
            if sys.stdout.isatty():
                ConsoleUI.print_targets(payload)
            else:
                print(json.dumps(payload, indent=2))
            return
        if args.engagement_command == "scan":
            outputs = run_engagement_scan(args.engagement, args.profile, args.target, args.all)
            if sys.stdout.isatty():
                ConsoleUI.print_scan_reports(outputs)
            else:
                print(json.dumps(outputs, indent=2))
            return

    if args.command == "note" and args.note_command == "add":
        payload = manager.add_note(args.engagement, args.target, args.text, args.category, args.tags)
        if sys.stdout.isatty():
            ConsoleUI.print_record("Note Added", payload)
        else:
            print(json.dumps(payload, indent=2))
        return

    if args.command == "evidence" and args.evidence_command == "add":
        payload = manager.add_evidence(
            args.engagement,
            args.target,
            description=args.description,
            text=args.text,
            file_path=args.file,
        )
        if sys.stdout.isatty():
            ConsoleUI.print_record("Evidence Added", payload)
        else:
            print(
                json.dumps(
                    payload,
                    indent=2,
                )
            )
        return

    interactive_main()


if __name__ == "__main__":
    main()
