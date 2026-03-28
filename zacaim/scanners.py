"""Host and web scanning pipelines."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .analyzers import FindingsAnalyzer
from .constants import COMMON_SECURITY_HEADERS, HOST_PROFILES, KNOWN_WEB_PATHS, WEB_PORT_HINTS, WEB_PROFILES
from .models import HttpEndpoint, ServiceFinding, TargetSummary
from .parsers import NmapParser, parse_robots_txt, parse_sitemap_xml
from .runners import CommandRunner
from .validators import TargetValidator, append_unique, is_root, normalize_url, now_iso, slugify


class TargetScanner:
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.runner = CommandRunner(session_dir)

    def scan(self, raw_target: str, profile: str) -> TargetSummary:
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
                "robots": [],
                "sitemaps": [],
                "testssl_highlights": [],
                "tool_notes": [],
            },
        )

        xml_path = self.session_dir / "raw" / "nmap.xml"
        text_path = self.session_dir / "raw" / "nmap.txt"
        nmap_command = self._build_nmap_command(profile_config, target, xml_path, text_path)
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
        summary.open_services = parsed["services"]  # type: ignore[assignment]
        summary.os_guess = str(parsed["os_guess"])
        summary.host_observations["service_groups"] = self._service_group_counts(summary.open_services)

        if profile_config["reverse_dns"]:
            self._probe_reverse_dns(target, summary)
        if profile_config["ssh_keyscan"]:
            self._probe_ssh_keys(target, summary.open_services, summary)

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
        summary.recommended_steps = self._recommended_steps(summary)
        summary.findings = FindingsAnalyzer.generate(summary)
        return summary

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

    def scan(self, raw_url: str, profile: str = "standard") -> TargetSummary:
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
                "interesting_urls": [],
                "related_hosts": [],
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
        if profile_config["http_probe"]:
            self._target_scanner._probe_http_endpoint(endpoint, summary)
        if profile_config["tls_probe"]:
            self._target_scanner._probe_tls(endpoint, summary)
        if profile_config["whatweb"]:
            self._target_scanner._probe_whatweb(endpoint, summary)
        if profile_config["httpx"]:
            self._probe_httpx(endpoint, summary)
        if profile_config["known_paths"]:
            self._probe_known_paths(endpoint, summary)
        if profile_config["wafw00f"]:
            self._probe_wafw00f(endpoint, summary)
        if profile_config["katana"]:
            self._probe_katana(endpoint, summary, deep=bool(profile_config["katana_deep"]))
        if profile_config["testssl"]:
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
            parsed_response = self._split_http_response(content)
            status_code = parsed_response["status_code"]
            body = parsed_response["body"]
            if not status_code.startswith(("2", "3")):
                continue

            append_unique(summary.web_observations["path_hits"], path)
            append_unique(summary.web_observations["interesting_urls"], url)
            if path == "/robots.txt":
                robots = parse_robots_txt(body, source_url=url)
                if robots.get("group_count") or robots.get("sitemaps"):
                    summary.web_observations["robots"].append(robots)
                append_unique(
                    summary.web_observations["interesting_urls"],
                    *(str(item) for item in robots.get("interesting_urls", [])[:20]),
                )
            elif path == "/sitemap.xml":
                sitemap = parse_sitemap_xml(body, source_url=url)
                summary.web_observations["sitemaps"].append(sitemap)
                append_unique(
                    summary.web_observations["interesting_urls"],
                    *(str(item) for item in sitemap.get("sample_urls", [])[:20]),
                )
                append_unique(
                    summary.web_observations["interesting_urls"],
                    *(str(item) for item in sitemap.get("child_sitemaps", [])[:20]),
                )

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
