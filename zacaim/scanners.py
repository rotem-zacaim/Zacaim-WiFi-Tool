"""Host and web scanning pipelines."""

from __future__ import annotations

import hashlib
import json
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

from .analyzers import FindingsAnalyzer
from .constants import COMMON_SECURITY_HEADERS, HOST_PROFILES, KNOWN_WEB_PATHS, WEB_PORT_HINTS, WEB_PROFILES
from .models import HttpEndpoint, ServiceFinding, TargetSummary
from .parsers import NmapParser, parse_robots_txt, parse_security_txt, parse_sitemap_xml
from .runners import CommandRunner
from .validators import TargetValidator, append_unique, is_root, normalize_url, now_iso, slugify


class TargetScanner:
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.runner = CommandRunner(session_dir)

    def scan(self, raw_target: str, profile: str, tracker: object | None = None) -> TargetSummary:
        if profile not in HOST_PROFILES:
            raise ValueError(f"Unsupported profile '{profile}'. Choose one of: {', '.join(HOST_PROFILES)}")

        target = TargetValidator.normalize(raw_target)
        profile_config = HOST_PROFILES[profile]
        summary = TargetSummary(
            target=target,
            target_kind=TargetValidator.kind(target),
            session_id=self.session_dir.name,
            profile=profile,
            started_at=now_iso(),
            output_dir=str(self.session_dir),
            host_observations={
                "reverse_dns": [],
                "dnsx_records": [],
                "port_inventory": [],
                "ssh_host_keys": [],
                "tls_highlights": [],
                "smb_highlights": [],
                "ldap_highlights": [],
                "snmp_highlights": [],
                "rdp_highlights": [],
                "ike_highlights": [],
                "service_groups": {},
                "tool_notes": [],
            },
            web_observations={
                "profile": "embedded-host-enrichment",
                "interesting_urls": [],
                "related_hosts": [],
                "dnsx_records": [],
                "route_highlights": [],
                "contacts": [],
                "content_types": [],
                "waf": "",
                "crawl_url_count": 0,
                "crawl_sample": [],
                "path_hits": [],
                "robots": [],
                "sitemaps": [],
                "testssl_highlights": [],
                "tool_notes": [],
            },
        )

        plan = self._build_host_plan(profile_config, target)
        if tracker is not None and hasattr(tracker, "start"):
            tracker.start()
        try:
            for step in plan:
                step_id = str(step["id"])
                if tracker is not None and hasattr(tracker, "start_step"):
                    tracker.start_step(step_id, str(step.get("note", "")))
                try:
                    previous_results = len(summary.command_results)
                    step["fn"](summary)  # type: ignore[index]
                    new_results = summary.command_results[previous_results:]
                    status = "done"
                    if new_results and all(result.skipped for result in new_results):
                        status = "skipped"
                    if tracker is not None and hasattr(tracker, "finish_step"):
                        tracker.finish_step(step_id, status)
                except Exception as exc:
                    summary.host_observations["tool_notes"].append(f"{step_id}: {exc}")
                    if tracker is not None and hasattr(tracker, "finish_step"):
                        tracker.finish_step(step_id, "error", str(exc))
        finally:
            if tracker is not None and hasattr(tracker, "stop"):
                tracker.stop()

        summary.recommended_steps = self._recommended_steps(summary)
        summary.findings = FindingsAnalyzer.generate(summary)
        return summary

    @classmethod
    def build_progress_plan(cls, raw_target: str, profile: str = "standard") -> list[dict[str, object]]:
        target = TargetValidator.normalize(raw_target)
        profile_config = HOST_PROFILES[profile]
        return [
            {"id": step["id"], "label": step["label"], "eta": step["eta"], "note": step.get("note", "")}
            for step in cls(Path("."))._build_host_plan(profile_config, target)
        ]

    def _build_host_plan(self, profile_config: dict[str, object], target: str) -> list[dict[str, object]]:
        plan: list[dict[str, object]] = [
            {
                "id": "nmap",
                "label": "Nmap",
                "eta": 120.0 if profile_config["nmap_flags"] != ["-sV"] else 45.0,
                "fn": lambda summary: self._run_nmap(profile_config, target, summary),
                "note": "mapping open services and banners",
            }
        ]
        if profile_config["naabu"]:
            plan.append({"id": "naabu", "label": "Naabu", "eta": 35.0, "fn": lambda summary: self._probe_naabu_host(target, summary), "note": "verifying broad port exposure"})
        if profile_config["dnsx"]:
            plan.append({"id": "dnsx", "label": "dnsx", "eta": 12.0, "fn": lambda summary: self._probe_dnsx_host(target, summary), "note": "enriching DNS records"})
        if profile_config["reverse_dns"]:
            plan.append({"id": "reverse_dns", "label": "Reverse DNS", "eta": 8.0, "fn": lambda summary: self._probe_reverse_dns(target, summary), "note": "checking PTR and naming hints"})
        if profile_config["ssh_keyscan"]:
            plan.append({"id": "ssh_keyscan", "label": "SSH keyscan", "eta": 10.0, "fn": lambda summary: self._probe_ssh_keys(target, summary.open_services, summary), "note": "collecting host keys when SSH is exposed"})
        if profile_config["sslscan"]:
            plan.append({"id": "sslscan", "label": "sslscan", "eta": 45.0, "fn": lambda summary: self._probe_sslscan(target, summary.open_services, summary), "note": "reviewing exposed TLS services"})
        if profile_config["enum4linux_ng"]:
            plan.append({"id": "enum4linux", "label": "enum4linux-ng", "eta": 80.0, "fn": lambda summary: self._probe_enum4linux(target, summary.open_services, summary), "note": "checking SMB and Windows metadata"})
        if profile_config["ldapsearch"]:
            plan.append({"id": "ldapsearch", "label": "ldapsearch", "eta": 35.0, "fn": lambda summary: self._probe_ldapsearch(target, summary.open_services, summary), "note": "collecting LDAP root DSE details"})
        if profile_config["snmpwalk"]:
            plan.append({"id": "snmpwalk", "label": "snmpwalk", "eta": 45.0, "fn": lambda summary: self._probe_snmpwalk(target, summary.open_services, summary), "note": "checking public SNMP exposure"})
        if profile_config["rdpscan"]:
            plan.append({"id": "rdpscan", "label": "rdpscan", "eta": 25.0, "fn": lambda summary: self._probe_rdpscan(target, summary.open_services, summary), "note": "reviewing exposed RDP services"})
        if profile_config["ike_scan"]:
            plan.append({"id": "ike_scan", "label": "ike-scan", "eta": 25.0, "fn": lambda summary: self._probe_ike_scan(target, summary.open_services, summary), "note": "checking VPN / ISAKMP exposure"})
        if any(
            profile_config[key]
            for key in ["http_probe", "tls_probe", "whatweb", "httpx", "known_paths", "wafw00f", "katana", "testssl"]
        ):
            plan.append({"id": "web_enrich", "label": "Web enrichment", "eta": 140.0 if profile_config["katana"] else 55.0, "fn": lambda summary: self._run_web_enrichment(target, profile_config, summary), "note": "expanding discovered HTTP endpoints"})
        return plan

    def _run_nmap(self, profile_config: dict[str, object], target: str, summary: TargetSummary) -> None:
        xml_path = self.session_dir / "raw" / "nmap.xml"
        text_path = self.session_dir / "raw" / "nmap.txt"
        nmap_command = self._build_nmap_command(profile_config, target, xml_path, text_path)
        summary.command_results.append(
            self.runner.run(
                name=f"nmap_{summary.profile}",
                command=nmap_command,
                artifact_prefix=f"nmap_{summary.profile}",
                timeout=3600,
                required_tool="nmap",
            )
        )
        parsed = NmapParser.parse(xml_path)
        summary.open_services = parsed["services"]  # type: ignore[assignment]
        summary.os_guess = str(parsed["os_guess"])
        summary.host_observations["service_groups"] = self._service_group_counts(summary.open_services)

    def _run_web_enrichment(self, target: str, profile_config: dict[str, object], summary: TargetSummary) -> None:
        web_helper = WebScanner(self.session_dir)
        for endpoint in self._identify_http_endpoints(target, summary.open_services):
            self._probe_http_endpoint(endpoint, summary)
            if profile_config["tls_probe"]:
                self._probe_tls(endpoint, summary)
            if profile_config["whatweb"]:
                self._probe_whatweb(endpoint, summary)
            if profile_config["httpx"]:
                web_helper._probe_httpx(endpoint, summary)
            if profile_config["known_paths"]:
                web_helper._probe_known_paths(endpoint, summary)
            if profile_config["wafw00f"]:
                web_helper._probe_wafw00f(endpoint, summary)
            if profile_config["katana"]:
                web_helper._probe_katana(endpoint, summary, deep=bool(profile_config["katana_deep"]))
            if profile_config["testssl"]:
                web_helper._probe_testssl(endpoint, summary)
        summary.host_observations["tls_highlights"] = list(summary.web_observations.get("testssl_highlights", []))

    def _build_nmap_command(self, profile_config: dict[str, object], target: str, xml_path: Path, text_path: Path) -> list[str]:
        base = ["nmap", "-Pn", "--open", "-oX", str(xml_path), "-oN", str(text_path)]
        flags = list(profile_config["nmap_flags"])  # type: ignore[arg-type]
        if "-O" in flags and not is_root():
            flags.remove("-O")
        return base + flags + [target]

    def _service_group_counts(self, services: list[ServiceFinding]) -> dict[str, int]:
        counts = {"web": 0, "admin": 0, "files": 0, "database": 0}
        from .constants import ADMIN_SERVICES, DATABASE_SERVICES, FILE_SERVICES

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

        names: list[str] = []
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

    def _probe_naabu_host(self, target: str, summary: TargetSummary) -> None:
        prefix = slugify(f"naabu_host_{target}")
        result = self.runner.run(
            name=f"naabu_host_{prefix}",
            command=["naabu", "-host", target, "-top-ports", "200", "-silent"],
            artifact_prefix=f"naabu_host_{prefix}",
            timeout=90,
            required_tool="naabu",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            inventory: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(inventory, cleaned)
            summary.host_observations["port_inventory"] = inventory[:40]

    def _probe_dnsx_host(self, target: str, summary: TargetSummary) -> None:
        input_path = self.session_dir / "raw" / f"dnsx_{slugify(target)}.txt"
        input_path.write_text(f"{target}\n", encoding="utf-8")
        prefix = slugify(f"dnsx_host_{target}")
        result = self.runner.run(
            name=f"dnsx_host_{prefix}",
            command=["dnsx", "-silent", "-resp-only", "-a", "-aaaa", "-cname", "-recon", "-l", str(input_path)],
            artifact_prefix=f"dnsx_host_{prefix}",
            timeout=45,
            required_tool="dnsx",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            records: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(records, cleaned)
            summary.host_observations["dnsx_records"] = records[:20]

    def _probe_ssh_keys(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        ssh_ports = sorted({service.port for service in services if service.service.lower() == "ssh" or service.port == 22})
        keys: list[str] = []
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

    def _probe_sslscan(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        highlights: list[str] = []
        tls_ports = sorted({service.port for service in services if "https" in service.service.lower() or service.tunnel.lower() == "ssl" or service.port in {443, 465, 636, 8443}})
        for port in tls_ports[:4]:
            prefix = f"sslscan_{port}"
            result = self.runner.run(
                name=prefix,
                command=["sslscan", f"{target}:{port}"],
                artifact_prefix=prefix,
                timeout=90,
                required_tool="sslscan",
            )
            summary.command_results.append(result)
            if result.stdout_path and Path(result.stdout_path).exists():
                for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                    cleaned = line.strip()
                    lower = cleaned.lower()
                    if cleaned and any(marker in lower for marker in ["tls", "certificate", "accepted", "preferred"]):
                        append_unique(highlights, cleaned[:200])
        summary.host_observations["tls_highlights"] = list(dict.fromkeys(summary.host_observations.get("tls_highlights", []) + highlights))[:12]

    def _probe_enum4linux(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        if not any(service.port in {139, 445} or service.service.lower() in {"smb", "microsoft-ds", "netbios-ssn"} for service in services):
            return
        result = self.runner.run(
            name="enum4linux_ng",
            command=["enum4linux-ng", "-A", target],
            artifact_prefix="enum4linux_ng",
            timeout=180,
            required_tool="enum4linux-ng",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            highlights: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned and any(token in cleaned.lower() for token in ["domain", "share", "user", "group", "os:"]):
                    append_unique(highlights, cleaned[:220])
            summary.host_observations["smb_highlights"] = highlights[:15]

    def _probe_ldapsearch(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        ldap_ports = sorted({service.port for service in services if service.port in {389, 636} or "ldap" in service.service.lower()})
        highlights: list[str] = []
        for port in ldap_ports[:2]:
            result = self.runner.run(
                name=f"ldapsearch_{port}",
                command=["ldapsearch", "-x", "-H", f"ldap://{target}:{port}", "-s", "base"],
                artifact_prefix=f"ldapsearch_{port}",
                timeout=45,
                required_tool="ldapsearch",
            )
            summary.command_results.append(result)
            if result.stdout_path and Path(result.stdout_path).exists():
                for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                    cleaned = line.strip()
                    if cleaned.lower().startswith(("namingcontexts:", "defaultnamingcontext:", "rootdomainnamingcontext:", "dn:")):
                        append_unique(highlights, cleaned[:220])
        summary.host_observations["ldap_highlights"] = highlights[:12]

    def _probe_snmpwalk(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        if not any(service.port == 161 or service.service.lower() == "snmp" for service in services):
            return
        result = self.runner.run(
            name="snmpwalk",
            command=["snmpwalk", "-v2c", "-c", "public", target],
            artifact_prefix="snmpwalk",
            timeout=60,
            required_tool="snmpwalk",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            highlights: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned and any(token in cleaned.lower() for token in ["sysdescr", "sysname", "contact", "location"]):
                    append_unique(highlights, cleaned[:220])
            summary.host_observations["snmp_highlights"] = highlights[:10]

    def _probe_rdpscan(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        if not any(service.port == 3389 or service.service.lower() in {"rdp", "ms-wbt-server"} for service in services):
            return
        result = self.runner.run(
            name="rdpscan",
            command=["rdpscan", target],
            artifact_prefix="rdpscan",
            timeout=45,
            required_tool="rdpscan",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            highlights: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(highlights, cleaned[:220])
            summary.host_observations["rdp_highlights"] = highlights[:10]

    def _probe_ike_scan(self, target: str, services: list[ServiceFinding], summary: TargetSummary) -> None:
        if not any(service.port == 500 or "isakmp" in service.service.lower() for service in services):
            return
        result = self.runner.run(
            name="ike_scan",
            command=["ike-scan", target],
            artifact_prefix="ike_scan",
            timeout=45,
            required_tool="ike-scan",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            highlights: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(highlights, cleaned[:220])
            summary.host_observations["ike_highlights"] = highlights[:10]

    def _recommended_steps(self, summary: TargetSummary) -> list[str]:
        steps: list[str] = []
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

    def _identify_http_endpoints(self, target: str, services: list[ServiceFinding]) -> list[HttpEndpoint]:
        endpoints: list[HttpEndpoint] = []
        for service in services:
            service_name = service.service.lower()
            looks_like_web = "http" in service_name or service.port in WEB_PORT_HINTS or service.tunnel.lower() == "ssl"
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
                header_match = re.search(rf"^{re.escape(header_name)}:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
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

    def scan(self, raw_url: str, profile: str = "standard", tracker: object | None = None) -> TargetSummary:
        if profile not in WEB_PROFILES:
            raise ValueError(f"Unsupported web profile '{profile}'. Choose one of: {', '.join(WEB_PROFILES)}")

        target = normalize_url(raw_url)
        profile_config = WEB_PROFILES[profile]
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
                "resolved_addresses": [],
                "reverse_dns": [],
                "certificate_names": [],
                "interesting_urls": [],
                "related_hosts": [],
                "dnsx_records": [],
                "port_inventory": [],
                "external_domains": [],
                "content_types": [],
                "cookies": [],
                "redirect_chain": [],
                "html_comments": [],
                "forms": [],
                "scripts": [],
                "page_links": [],
                "emails": [],
                "contacts": [],
                "meta_generators": [],
                "favicon_hash": "",
                "body_word_count": 0,
                "waf": "",
                "subdomains": [],
                "historical_urls": [],
                "ffuf_hits": [],
                "nikto_highlights": [],
                "route_highlights": [],
                "crawl_url_count": 0,
                "crawl_sample": [],
                "path_hits": [],
                "robots": [],
                "sitemaps": [],
                "security_txt": [],
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
        plan = self._build_web_plan(profile_config, endpoint)
        if tracker is not None and hasattr(tracker, "start"):
            tracker.start()
        try:
            for step in plan:
                step_id = str(step["id"])
                if tracker is not None and hasattr(tracker, "start_step"):
                    tracker.start_step(step_id, str(step.get("note", "")))
                try:
                    previous_results = len(summary.command_results)
                    step["fn"](endpoint, summary)  # type: ignore[index]
                    new_results = summary.command_results[previous_results:]
                    status = "done"
                    if new_results and all(result.skipped for result in new_results):
                        status = "skipped"
                    if tracker is not None and hasattr(tracker, "finish_step"):
                        tracker.finish_step(step_id, status)
                except Exception as exc:
                    summary.web_observations["tool_notes"].append(f"{step_id}: {exc}")
                    if tracker is not None and hasattr(tracker, "finish_step"):
                        tracker.finish_step(step_id, "error", str(exc))
        finally:
            if tracker is not None and hasattr(tracker, "stop"):
                tracker.stop()

        summary.recommended_steps = self._recommended_steps(summary)
        summary.findings = FindingsAnalyzer.generate(summary)
        return summary

    @classmethod
    def build_progress_plan(cls, raw_url: str, profile: str = "standard") -> list[dict[str, object]]:
        target = normalize_url(raw_url)
        profile_config = WEB_PROFILES[profile]
        endpoint = HttpEndpoint(url=target["url"])
        return [
            {"id": step["id"], "label": step["label"], "eta": step["eta"], "note": step.get("note", "")}
            for step in cls(Path("."))._build_web_plan(profile_config, endpoint)
        ]

    def _build_web_plan(self, profile_config: dict[str, object], endpoint: HttpEndpoint) -> list[dict[str, object]]:
        plan: list[dict[str, object]] = [
            {"id": "dns_resolve", "label": "DNS resolve", "eta": 3.0, "fn": self._probe_dns, "note": "collecting A/AAAA answers"},
            {"id": "reverse_dns", "label": "Reverse DNS", "eta": 3.0, "fn": self._probe_reverse_dns, "note": "checking host naming hints"},
            {"id": "dnsx", "label": "dnsx", "eta": 8.0, "fn": self._probe_dnsx if profile_config["dnsx"] else self._noop, "note": "enriching DNS records"},
            {"id": "naabu", "label": "Naabu", "eta": 12.0, "fn": self._probe_naabu if profile_config["naabu"] else self._noop, "note": "checking web-adjacent ports"},
            {"id": "http_probe", "label": "HTTP probe", "eta": 12.0, "fn": self._target_scanner._probe_http_endpoint, "note": "fetching headers and body"},
            {"id": "response_parse", "label": "Response analysis", "eta": 4.0, "fn": self._analyze_http_content, "note": "extracting links, forms, cookies, comments"},
            {"id": "cookie_review", "label": "Cookie review", "eta": 2.0, "fn": self._derive_cookie_summary, "note": "summarizing cookies and redirects"},
            {"id": "content_metrics", "label": "Content metrics", "eta": 2.0, "fn": self._derive_content_metrics, "note": "measuring body and content signals"},
            {"id": "favicon", "label": "Favicon fingerprint", "eta": 6.0, "fn": self._probe_favicon, "note": "hashing favicon content"},
        ]
        if profile_config["tls_probe"]:
            plan.extend(
                [
                    {"id": "tls_probe", "label": "TLS probe", "eta": 12.0, "fn": self._target_scanner._probe_tls, "note": "opening TLS session"},
                    {"id": "cert_parse", "label": "Certificate names", "eta": 3.0, "fn": self._parse_tls_artifact, "note": "extracting certificate SANs"},
                ]
            )
        if profile_config["whatweb"]:
            plan.append({"id": "whatweb", "label": "WhatWeb", "eta": 15.0, "fn": self._target_scanner._probe_whatweb, "note": "technology hints"})
        if profile_config["httpx"]:
            plan.append({"id": "httpx", "label": "httpx", "eta": 15.0, "fn": self._probe_httpx, "note": "status, redirects, tech detect"})
        if profile_config["ffuf"]:
            plan.append({"id": "ffuf", "label": "ffuf", "eta": 35.0, "fn": self._probe_ffuf, "note": "light content discovery"})
        if profile_config["nikto"]:
            plan.append({"id": "nikto", "label": "Nikto", "eta": 45.0, "fn": self._probe_nikto, "note": "web server checks"})
        plan.extend(
            [
                {"id": "robots", "label": "robots.txt", "eta": 6.0, "fn": self._probe_robots, "note": "parsing crawler directives"},
                {"id": "sitemap", "label": "sitemap.xml", "eta": 6.0, "fn": self._probe_sitemap, "note": "mapping XML route inventory"},
                {"id": "security_wk", "label": "security.txt", "eta": 6.0, "fn": self._probe_security_txt_well_known, "note": "checking disclosure policy file"},
                {"id": "security_root", "label": "root security.txt", "eta": 6.0, "fn": self._probe_security_txt_root, "note": "checking alternate disclosure file"},
            ]
        )
        if profile_config["subfinder"]:
            plan.append({"id": "subfinder", "label": "Subfinder", "eta": 20.0, "fn": self._probe_subfinder, "note": "passive subdomain enrichment"})
        if profile_config["gau"]:
            plan.append({"id": "gau", "label": "Historical URLs", "eta": 20.0, "fn": self._probe_gau, "note": "collecting archived URLs"})
        if profile_config["wafw00f"]:
            plan.append({"id": "wafw00f", "label": "WAF detect", "eta": 25.0, "fn": self._probe_wafw00f, "note": "checking for edge protections"})
        plan.extend(
            [
                {"id": "headers_score", "label": "Header policy", "eta": 2.0, "fn": self._derive_header_score, "note": "summarizing security header coverage"},
                {"id": "contact_extract", "label": "Contact extract", "eta": 2.0, "fn": self._derive_contact_summary, "note": "reviewing exposed emails and security contacts"},
                {"id": "domain_extract", "label": "Domain extract", "eta": 2.0, "fn": self._derive_external_domains, "note": "collecting related domains"},
                {"id": "link_cluster", "label": "Route inventory", "eta": 2.0, "fn": self._derive_interesting_routes, "note": "clustering high-signal routes"},
            ]
        )
        if profile_config["katana"]:
            plan.append({"id": "katana", "label": "Katana crawl", "eta": 120.0 if profile_config["katana_deep"] else 75.0, "fn": lambda e, s: self._probe_katana(e, s, deep=bool(profile_config["katana_deep"])), "note": "crawling in-scope routes"})
        if profile_config["testssl"]:
            plan.append({"id": "testssl", "label": "TLS review", "eta": 180.0, "fn": self._probe_testssl, "note": "deep TLS review"})
        return plan

    def _probe_dns(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        addresses: list[str] = []
        try:
            for item in socket.getaddrinfo(host, None):
                candidate = item[4][0]
                append_unique(addresses, candidate)
        except socket.gaierror:
            summary.web_observations["tool_notes"].append("DNS resolution failed.")
        summary.web_observations["resolved_addresses"] = addresses[:10]
        append_unique(summary.web_observations["related_hosts"], *addresses[:10])

    def _probe_dnsx(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        input_path = self.session_dir / "raw" / f"dnsx_web_{slugify(host)}.txt"
        input_path.write_text(f"{host}\n", encoding="utf-8")
        prefix = slugify(f"dnsx_{host}")
        result = self.runner.run(
            name=f"dnsx_{prefix}",
            command=["dnsx", "-silent", "-resp-only", "-a", "-aaaa", "-cname", "-recon", "-l", str(input_path)],
            artifact_prefix=f"dnsx_{prefix}",
            timeout=30,
            required_tool="dnsx",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            records: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(records, cleaned)
            summary.web_observations["dnsx_records"] = records[:20]
            append_unique(summary.web_observations["related_hosts"], *records[:10])

    def _probe_naabu(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        ports = sorted({parsed.port or 443, 80, 443, 8080, 8443, 8000, 8008})
        prefix = slugify(f"naabu_{host}")
        result = self.runner.run(
            name=f"naabu_{prefix}",
            command=["naabu", "-host", host, "-ports", ",".join(str(port) for port in ports), "-silent"],
            artifact_prefix=f"naabu_{prefix}",
            timeout=40,
            required_tool="naabu",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            inventory: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(inventory, cleaned)
            summary.web_observations["port_inventory"] = inventory[:20]
            append_unique(summary.web_observations["interesting_urls"], *[f"{parsed.scheme}://{item}" for item in inventory[:10]])

    def _probe_reverse_dns(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        reverse_names: list[str] = []
        for address in summary.web_observations.get("resolved_addresses", [])[:3]:
            try:
                host, _, _ = socket.gethostbyaddr(address)
                append_unique(reverse_names, host)
            except OSError:
                continue
        summary.web_observations["reverse_dns"] = reverse_names[:10]

    def _analyze_http_content(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        prefix = slugify(endpoint.url)
        header_path = self.session_dir / "artifacts" / f"http_headers_{prefix}.stdout.txt"
        body_path = self.session_dir / "artifacts" / f"http_body_{prefix}.stdout.txt"
        if header_path.exists():
            header_text = header_path.read_text(encoding="utf-8", errors="replace")
            summary.web_observations["cookies"] = self._extract_cookies(header_text)
            summary.web_observations["redirect_chain"] = self._extract_redirects(header_text)
        if not body_path.exists():
            return
        body_text = body_path.read_text(encoding="utf-8", errors="replace")
        summary.web_observations["html_comments"] = self._extract_html_comments(body_text)
        summary.web_observations["forms"] = self._extract_forms(body_text, endpoint.url)
        summary.web_observations["scripts"] = self._extract_scripts(body_text, endpoint.url)
        summary.web_observations["page_links"] = self._extract_links(body_text, endpoint.url)
        summary.web_observations["emails"] = self._extract_emails(body_text)
        summary.web_observations["meta_generators"] = self._extract_meta_generators(body_text)
        summary.web_observations["body_word_count"] = len(re.findall(r"\w+", body_text))
        append_unique(summary.web_observations["interesting_urls"], *summary.web_observations["page_links"][:40])
        append_unique(summary.web_observations["interesting_urls"], *summary.web_observations["forms"][:20])
        append_unique(summary.web_observations["interesting_urls"], *summary.web_observations["scripts"][:20])

    def _probe_favicon(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        prefix = slugify(favicon_url)
        result = self.runner.run(
            name=f"favicon_{prefix}",
            command=["curl", "-ksL", "--max-time", "12", favicon_url],
            artifact_prefix=f"favicon_{prefix}",
            timeout=20,
            required_tool="curl",
        )
        summary.command_results.append(result)
        if result.returncode == 0 and result.stdout_path and Path(result.stdout_path).exists():
            data = Path(result.stdout_path).read_bytes()
            if data:
                summary.web_observations["favicon_hash"] = hashlib.sha256(data).hexdigest()[:20]
                append_unique(summary.web_observations["interesting_urls"], favicon_url)

    def _probe_ffuf(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        wordlist = Path("/usr/share/wordlists/dirb/common.txt")
        if not wordlist.exists():
            summary.web_observations["tool_notes"].append("ffuf skipped: common wordlist not found.")
            return
        parsed = urlparse(endpoint.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        prefix = slugify(f"ffuf_{endpoint.url}")
        result = self.runner.run(
            name=f"ffuf_{prefix}",
            command=[
                "ffuf",
                "-u",
                f"{base}/FUZZ",
                "-w",
                str(wordlist),
                "-mc",
                "200,204,301,302,307,401,403",
                "-s",
            ],
            artifact_prefix=f"ffuf_{prefix}",
            timeout=90,
            required_tool="ffuf",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            hits: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned and "FUZZ" not in cleaned:
                    append_unique(hits, cleaned[:200])
            summary.web_observations["ffuf_hits"] = hits[:20]

    def _probe_nikto(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        prefix = slugify(f"nikto_{endpoint.url}")
        result = self.runner.run(
            name=f"nikto_{prefix}",
            command=["nikto", "-h", endpoint.url, "-nointeractive"],
            artifact_prefix=f"nikto_{prefix}",
            timeout=180,
            required_tool="nikto",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            highlights: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned.startswith("+") or "OSVDB" in cleaned or "Nikto" in cleaned:
                    append_unique(highlights, cleaned[:220])
            summary.web_observations["nikto_highlights"] = highlights[:15]

    def _probe_subfinder(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        if host.count(".") < 1:
            return
        apex = ".".join(host.split(".")[-2:])
        prefix = slugify(f"subfinder_{apex}")
        result = self.runner.run(
            name=f"subfinder_{prefix}",
            command=["subfinder", "-silent", "-d", apex],
            artifact_prefix=f"subfinder_{prefix}",
            timeout=60,
            required_tool="subfinder",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            subdomains: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(subdomains, cleaned)
            summary.web_observations["subdomains"] = subdomains[:30]
            append_unique(summary.web_observations["related_hosts"], *subdomains[:30])

    def _probe_gau(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        prefix = slugify(f"gau_{host}")
        result = self.runner.run(
            name=f"gau_{prefix}",
            command=["gau", "--subs", host],
            artifact_prefix=f"gau_{prefix}",
            timeout=60,
            required_tool="gau",
        )
        summary.command_results.append(result)
        if result.stdout_path and Path(result.stdout_path).exists():
            historical_urls: list[str] = []
            for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned:
                    append_unique(historical_urls, cleaned)
            summary.web_observations["historical_urls"] = historical_urls[:40]
            append_unique(summary.web_observations["interesting_urls"], *historical_urls[:40])

    def _parse_tls_artifact(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        if not endpoint.url.startswith("https://"):
            return
        prefix = slugify(endpoint.url)
        artifact = self.session_dir / "artifacts" / f"tls_probe_{prefix}.stdout.txt"
        if not artifact.exists():
            return
        text = artifact.read_text(encoding="utf-8", errors="replace")
        names = re.findall(r"(?:DNS:|CN=)([A-Za-z0-9*._-]+\.[A-Za-z0-9._-]+)", text)
        certificate_names: list[str] = []
        for name in names:
            append_unique(certificate_names, name)
        summary.web_observations["certificate_names"] = certificate_names[:20]
        append_unique(summary.web_observations["related_hosts"], *certificate_names[:20])

    def _probe_robots(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        self._probe_known_path(endpoint, summary, "/robots.txt")

    def _probe_sitemap(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        self._probe_known_path(endpoint, summary, "/sitemap.xml")

    def _probe_security_txt_well_known(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        self._probe_known_path(endpoint, summary, "/.well-known/security.txt")

    def _probe_security_txt_root(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        self._probe_known_path(endpoint, summary, "/security.txt")

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

        lines = [line.strip() for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
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
        for path in KNOWN_WEB_PATHS:
            self._probe_known_path(endpoint, summary, path)

    def _probe_known_path(self, endpoint: HttpEndpoint, summary: TargetSummary, path: str) -> None:
        base = endpoint.url.rstrip("/")
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
            return

        content = Path(result.stdout_path).read_text(encoding="utf-8", errors="replace")
        parsed_response = self._split_http_response(content)
        status_code = parsed_response["status_code"]
        body = parsed_response["body"]
        if not status_code.startswith(("2", "3")):
            return

        append_unique(summary.web_observations["path_hits"], path)
        append_unique(summary.web_observations["interesting_urls"], url)
        if path == "/robots.txt":
            robots = parse_robots_txt(body, source_url=url)
            if robots.get("group_count") or robots.get("sitemaps"):
                summary.web_observations["robots"].append(robots)
            append_unique(summary.web_observations["interesting_urls"], *(str(item) for item in robots.get("interesting_urls", [])[:20]))
        elif path == "/sitemap.xml":
            sitemap = parse_sitemap_xml(body, source_url=url)
            summary.web_observations["sitemaps"].append(sitemap)
            append_unique(summary.web_observations["interesting_urls"], *(str(item) for item in sitemap.get("sample_urls", [])[:20]))
            append_unique(summary.web_observations["interesting_urls"], *(str(item) for item in sitemap.get("child_sitemaps", [])[:20]))
        elif path in {"/.well-known/security.txt", "/security.txt"}:
            security_txt = parse_security_txt(body, source_url=url)
            if security_txt.get("field_count"):
                summary.web_observations["security_txt"].append(security_txt)
                append_unique(summary.web_observations["interesting_urls"], *(str(item) for item in security_txt.get("contacts", [])[:10]))

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
        result = self.runner.run(
            name=f"katana_{prefix}",
            command=[
                "katana",
                "-u",
                endpoint.url,
                "-d",
                "5" if deep else "3",
                "-jc",
                "-kf",
                "robotstxt,sitemapxml",
                "-iqp",
                "-j",
                "-ct",
                "4m" if deep else "2m",
            ],
            artifact_prefix=f"katana_{prefix}",
            timeout=360 if deep else 180,
            required_tool="katana",
        )
        summary.command_results.append(result)
        if not result.stdout_path or not Path(result.stdout_path).exists():
            return

        discovered: list[str] = []
        for line in Path(result.stdout_path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            request_data = payload.get("request") or {}
            candidate = payload.get("url") or request_data.get("endpoint") or request_data.get("url") or ""
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

        highlights: list[str] = []
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

    def _recommended_steps(self, summary: TargetSummary) -> list[str]:
        steps: list[str] = []
        observations = summary.web_observations
        if observations.get("waf"):
            steps.append("Account for the identified WAF/WAAP before planning deeper validation or rate-heavy workflows.")
        if observations.get("forms"):
            steps.append("Review discovered forms and authentication flows before moving into deeper manual validation.")
        if observations.get("security_txt"):
            steps.append("Use parsed security.txt contacts and policy metadata to understand the site's disclosure surface.")
        if observations.get("crawl_url_count", 0) > 20:
            steps.append("Review the crawl sample and group endpoints by auth, admin, API, and static asset patterns.")
        if any(int(item.get("disallow_count", 0) or 0) > 0 for item in observations.get("robots", [])):
            steps.append("Review parsed robots.txt directives for admin, private, or debug-style routes worth validating manually.")
        if any(int(item.get("url_count", 0) or 0) > 0 for item in observations.get("sitemaps", [])):
            steps.append("Use parsed sitemap entries as a coverage baseline and compare them against the crawler output.")
        if any(url.lower().endswith(("openapi.json", "swagger.json")) for url in observations.get("interesting_urls", [])):
            steps.append("The target appears to expose API documentation. Consider an API-specific review flow next.")
        if any("graphql" in url.lower() for url in observations.get("interesting_urls", [])):
            steps.append("GraphQL-style routes were observed. Confirm schema exposure and auth behavior manually.")
        if any(path in observations.get("path_hits", []) for path in ["/robots.txt", "/sitemap.xml"]):
            steps.append("Use robots.txt and sitemap.xml as seeds for manual review and coverage validation.")
        if not steps:
            steps.append("Review the collected headers, technologies, and crawl output to choose the next scoped web checks.")
        return steps

    def _derive_header_score(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        header_count = 0
        for item in summary.http_endpoints:
            if item.url == endpoint.url:
                header_count = len(item.security_headers)
                break
        summary.web_observations["header_score"] = f"{header_count}/{len(COMMON_SECURITY_HEADERS)}"

    def _derive_cookie_summary(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        summary.web_observations["cookie_count"] = len(summary.web_observations.get("cookies", []))
        summary.web_observations["redirect_count"] = len(summary.web_observations.get("redirect_chain", []))

    def _derive_content_metrics(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        summary.web_observations["form_count"] = len(summary.web_observations.get("forms", []))
        summary.web_observations["script_count"] = len(summary.web_observations.get("scripts", []))
        summary.web_observations["link_count"] = len(summary.web_observations.get("page_links", []))
        summary.web_observations["comment_count"] = len(summary.web_observations.get("html_comments", []))
        summary.web_observations["email_count"] = len(summary.web_observations.get("emails", []))

    def _derive_contact_summary(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        contacts: list[str] = []
        for item in summary.web_observations.get("emails", [])[:10]:
            append_unique(contacts, item)
        for entry in summary.web_observations.get("security_txt", []):
            for contact in entry.get("contacts", [])[:10]:
                append_unique(contacts, str(contact))
        summary.web_observations["contacts"] = contacts[:15]

    def _derive_external_domains(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        domains: list[str] = []
        for url in summary.web_observations.get("page_links", []) + summary.web_observations.get("scripts", []):
            candidate = urlparse(url).hostname or ""
            if candidate and candidate != host:
                append_unique(domains, candidate)
        summary.web_observations["external_domains"] = domains[:25]
        append_unique(summary.web_observations["related_hosts"], *domains[:25])

    def _derive_interesting_routes(self, endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        keywords = ("login", "admin", "api", "graphql", "swagger", "openapi", "dashboard", "auth")
        interesting: list[str] = []
        for url in summary.web_observations.get("interesting_urls", []):
            if any(keyword in url.lower() for keyword in keywords):
                append_unique(interesting, url)
        summary.web_observations["interesting_urls"] = list(summary.web_observations.get("interesting_urls", []))[:150]
        summary.web_observations["route_highlights"] = interesting[:25]

    @staticmethod
    def _noop(endpoint: HttpEndpoint, summary: TargetSummary) -> None:
        return

    @staticmethod
    def _split_http_response(content: str) -> dict[str, str]:
        normalized = content.replace("\r\n", "\n")
        header_blocks = re.findall(r"(HTTP/\d(?:\.\d)?\s+\d{3}.*?)(?:\n\n|\Z)", normalized, re.DOTALL)
        body = normalized
        if "\n\n" in normalized:
            body = normalized.rsplit("\n\n", 1)[-1]
        status_code = ""
        if header_blocks:
            last_block = header_blocks[-1]
            status_match = re.search(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", last_block, re.MULTILINE)
            if status_match:
                status_code = status_match.group(1)
        return {"status_code": status_code, "body": body}

    @staticmethod
    def _extract_cookies(header_text: str) -> list[str]:
        cookies = re.findall(r"^Set-Cookie:\s*([^=;,\r\n]+)", header_text, re.IGNORECASE | re.MULTILINE)
        result: list[str] = []
        for cookie in cookies:
            append_unique(result, cookie)
        return result[:20]

    @staticmethod
    def _extract_redirects(header_text: str) -> list[str]:
        redirects = re.findall(r"^Location:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
        result: list[str] = []
        for redirect in redirects:
            append_unique(result, redirect.strip())
        return result[:10]

    @staticmethod
    def _extract_html_comments(body_text: str) -> list[str]:
        comments = re.findall(r"<!--(.*?)-->", body_text, re.DOTALL)
        result: list[str] = []
        for comment in comments:
            normalized = re.sub(r"\s+", " ", comment).strip()
            if normalized:
                append_unique(result, normalized[:180])
        return result[:15]

    @staticmethod
    def _extract_forms(body_text: str, base_url: str) -> list[str]:
        forms = re.findall(r"<form[^>]+action=['\"]?([^'\"> ]+)", body_text, re.IGNORECASE)
        result: list[str] = []
        for form in forms:
            append_unique(result, form if form.startswith("http") else f"{base_url.rstrip('/')}/{form.lstrip('/')}")
        return result[:20]

    @staticmethod
    def _extract_scripts(body_text: str, base_url: str) -> list[str]:
        scripts = re.findall(r"<script[^>]+src=['\"]([^'\"]+)", body_text, re.IGNORECASE)
        result: list[str] = []
        for script in scripts:
            append_unique(result, script if script.startswith("http") else f"{base_url.rstrip('/')}/{script.lstrip('/')}")
        return result[:30]

    @staticmethod
    def _extract_links(body_text: str, base_url: str) -> list[str]:
        links = re.findall(r"""href=['"]([^'"]+)""", body_text, re.IGNORECASE)
        result: list[str] = []
        for link in links:
            if link.startswith("#") or link.startswith("javascript:"):
                continue
            append_unique(result, link if link.startswith("http") else f"{base_url.rstrip('/')}/{link.lstrip('/')}")
        return result[:50]

    @staticmethod
    def _extract_emails(body_text: str) -> list[str]:
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body_text)
        result: list[str] = []
        for email in emails:
            append_unique(result, email)
        return result[:20]

    @staticmethod
    def _extract_meta_generators(body_text: str) -> list[str]:
        generators = re.findall(r"""<meta[^>]+name=['"]generator['"][^>]+content=['"]([^'"]+)""", body_text, re.IGNORECASE)
        result: list[str] = []
        for generator in generators:
            append_unique(result, generator.strip())
        return result[:10]
