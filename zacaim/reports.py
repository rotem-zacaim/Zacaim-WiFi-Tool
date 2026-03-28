"""Report generation."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .constants import APP_NAME
from .filesystem import write_json, write_text
from .models import TargetSummary


class ReportBuilder:
    @staticmethod
    def build(summary: TargetSummary, session_dir: Path) -> dict[str, str]:
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
                security_headers = ", ".join(sorted(endpoint.security_headers)) if endpoint.security_headers else "n/a"
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
            for robots_entry in observations.get("robots", [])[:3]:
                lines.append(
                    "- robots.txt parsed: "
                    f"`user_agents={len(robots_entry.get('user_agents', []))} "
                    f"allow={robots_entry.get('allow_count', 0)} "
                    f"disallow={robots_entry.get('disallow_count', 0)}`"
                )
                if robots_entry.get("interesting_paths"):
                    lines.append(
                        f"  robots-paths: {', '.join(str(item) for item in robots_entry['interesting_paths'][:5])}"
                    )
            for sitemap_entry in observations.get("sitemaps", [])[:3]:
                lines.append(
                    "- sitemap.xml parsed: "
                    f"`kind={sitemap_entry.get('kind', 'invalid')} "
                    f"url_count={sitemap_entry.get('url_count', 0)} "
                    f"lastmod_count={sitemap_entry.get('lastmod_count', 0)}`"
                )
                for item in sitemap_entry.get("sample_urls", [])[:5]:
                    lines.append(f"  sitemap-url: {item}")
                for item in sitemap_entry.get("child_sitemaps", [])[:5]:
                    lines.append(f"  child-sitemap: {item}")
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
