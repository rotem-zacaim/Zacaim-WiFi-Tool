"""Finding generation and recommendation helpers."""

from __future__ import annotations

from .constants import ADMIN_SERVICES, DATABASE_SERVICES, FILE_SERVICES
from .models import Finding, TargetSummary


class FindingsAnalyzer:
    @staticmethod
    def generate(summary: TargetSummary) -> list[Finding]:
        findings: list[Finding] = []
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

            if endpoint.status_code:
                findings.append(
                    Finding(
                        title=f"HTTP response observed from {endpoint.url}",
                        severity="info",
                        category="web",
                        description=f"The endpoint responded with HTTP status {endpoint.status_code}.",
                        evidence=[endpoint.url, f"status={endpoint.status_code}"],
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

        if web_observations.get("certificate_names"):
            findings.append(
                Finding(
                    title="TLS certificate names collected",
                    severity="info",
                    category="web",
                    description="The scan extracted one or more certificate names from the TLS handshake output.",
                    evidence=[str(item) for item in web_observations.get("certificate_names", [])[:4]],
                    follow_up="Compare SAN/CN values against the engagement scope and related host inventory.",
                )
            )

        if web_observations.get("dnsx_records"):
            findings.append(
                Finding(
                    title="DNS record enrichment captured for web target",
                    severity="info",
                    category="web",
                    description="The web scan collected additional DNS-style answers or aliases for the target host.",
                    evidence=[str(item) for item in web_observations.get("dnsx_records", [])[:4]],
                    follow_up="Compare the enriched DNS data with CDN hints, certificates, and related hosts before expanding scope.",
                )
            )

        if web_observations.get("port_inventory"):
            findings.append(
                Finding(
                    title="Additional web-adjacent ports observed",
                    severity="info",
                    category="web",
                    description="A lightweight port check identified one or more ports adjacent to the target URL.",
                    evidence=[str(item) for item in web_observations.get("port_inventory", [])[:5]],
                    follow_up="Confirm which of the observed ports are in scope and whether they host separate applications or redirects.",
                )
            )

        if web_observations.get("subdomains"):
            findings.append(
                Finding(
                    title="Related subdomains discovered",
                    severity="info",
                    category="web",
                    description="Passive subdomain enrichment identified additional related hostnames.",
                    evidence=[str(item) for item in web_observations.get("subdomains", [])[:5]],
                    follow_up="Review whether the related subdomains are in scope and worth scanning separately.",
                )
            )

        if web_observations.get("historical_urls"):
            findings.append(
                Finding(
                    title="Historical URLs collected",
                    severity="info",
                    category="web",
                    description="Archived or historical URL sources exposed additional candidate routes.",
                    evidence=[str(item) for item in web_observations.get("historical_urls", [])[:5]],
                    follow_up="Compare historical routes against the current crawl to identify legacy or hidden paths.",
                )
            )

        if web_observations.get("ffuf_hits"):
            findings.append(
                Finding(
                    title="Content discovery hits observed",
                    severity="info",
                    category="web",
                    description="Light content discovery identified one or more reachable routes.",
                    evidence=[str(item) for item in web_observations.get("ffuf_hits", [])[:5]],
                    follow_up="Review the discovered paths for auth boundaries, admin functions, and exposed files.",
                )
            )

        if web_observations.get("nikto_highlights"):
            findings.append(
                Finding(
                    title="Nikto server observations captured",
                    severity="info",
                    category="web",
                    description="Nikto returned one or more server-side observations or banner checks.",
                    evidence=[str(item) for item in web_observations.get("nikto_highlights", [])[:4]],
                    follow_up="Validate the reported web server observations manually before drawing conclusions.",
                )
            )

        if web_observations.get("security_txt"):
            findings.append(
                Finding(
                    title="security.txt disclosure metadata discovered",
                    severity="info",
                    category="web",
                    description="The target exposed a security.txt file with contact or policy metadata.",
                    evidence=[str(item) for item in web_observations.get("security_txt", [])[0].get("contacts", [])[:3]],
                    follow_up="Review the published contacts, policy links, and disclosure workflow information.",
                )
            )

        if web_observations.get("forms"):
            findings.append(
                Finding(
                    title="HTML forms discovered",
                    severity="info",
                    category="web",
                    description="The response body exposed one or more forms that may indicate login, search, or submission flows.",
                    evidence=[str(item) for item in web_observations.get("forms", [])[:4]],
                    follow_up="Review form actions and parameters to map authentication and user-input surfaces.",
                )
            )

        if web_observations.get("external_domains"):
            findings.append(
                Finding(
                    title="External domains referenced by page resources",
                    severity="info",
                    category="web",
                    description="The page referenced one or more external domains through links or scripts.",
                    evidence=[str(item) for item in web_observations.get("external_domains", [])[:5]],
                    follow_up="Review whether the referenced domains are expected third parties or additional in-scope assets.",
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
            robots_entries = web_observations.get("robots", [])
            robots_evidence = [f"{summary.target.rstrip('/')}/robots.txt"]
            if robots_entries:
                first_entry = robots_entries[0]
                robots_evidence.extend(
                    [
                        f"disallow_count={first_entry.get('disallow_count', 0)}",
                        f"user_agents={len(first_entry.get('user_agents', []))}",
                    ]
                )
                robots_evidence.extend([str(item) for item in first_entry.get("interesting_paths", [])[:3]])
            findings.append(
                Finding(
                    title="robots.txt exposed crawler guidance",
                    severity="info",
                    category="web",
                    description="robots.txt was reachable and parsed, exposing crawler rules and potential route hints.",
                    evidence=robots_evidence,
                    follow_up="Review robots directives for sensitive or admin-adjacent routes before deeper manual validation.",
                )
            )
        if "/sitemap.xml" in path_hits:
            sitemap_entries = web_observations.get("sitemaps", [])
            sitemap_evidence = [f"{summary.target.rstrip('/')}/sitemap.xml"]
            if sitemap_entries:
                first_entry = sitemap_entries[0]
                sitemap_evidence.append(f"kind={first_entry.get('kind', 'invalid')}")
                sitemap_evidence.append(f"url_count={first_entry.get('url_count', 0)}")
                sitemap_evidence.extend([str(item) for item in first_entry.get("sample_urls", [])[:3]])
            findings.append(
                Finding(
                    title="sitemap.xml exposed route inventory",
                    severity="info",
                    category="web",
                    description="sitemap.xml was reachable and parsed, exposing route inventory or child sitemap references.",
                    evidence=sitemap_evidence,
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
                        url for url in interesting_urls if url.lower().endswith(("openapi.json", "swagger.json"))
                    ][:3],
                    follow_up="Review the exposed specification to map routes, auth schemes, and data models.",
                )
            )

        if web_observations.get("emails"):
            findings.append(
                Finding(
                    title="Email addresses exposed in response content",
                    severity="info",
                    category="web",
                    description="The response content exposed one or more email addresses.",
                    evidence=[str(item) for item in web_observations.get("emails", [])[:4]],
                    follow_up="Confirm whether the exposed contacts are expected and whether they reveal support or internal routing details.",
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

        if host_observations.get("dnsx_records"):
            findings.append(
                Finding(
                    title="DNS enrichment records collected",
                    severity="info",
                    category="fingerprint",
                    description="Additional DNS-style records or names were collected during host enrichment.",
                    evidence=[str(item) for item in host_observations.get("dnsx_records", [])[:4]],
                    follow_up="Correlate the discovered names or answers with certificates, PTR data, and scope records.",
                )
            )

        if host_observations.get("port_inventory"):
            findings.append(
                Finding(
                    title="Expanded port inventory captured",
                    severity="info",
                    category="fingerprint",
                    description="A fast port pass returned a broader list of candidate exposed ports for the host.",
                    evidence=[str(item) for item in host_observations.get("port_inventory", [])[:6]],
                    follow_up="Compare the broad port pass with Nmap output and review any ports that did not receive deeper fingerprinting.",
                )
            )

        if host_observations.get("smb_highlights"):
            findings.append(
                Finding(
                    title="SMB enumeration highlights captured",
                    severity="info",
                    category="files",
                    description="SMB-aware enrichment returned share, domain, or account metadata.",
                    evidence=[str(item) for item in host_observations.get("smb_highlights", [])[:4]],
                    follow_up="Review the SMB output for shares, hostnames, and naming context details.",
                )
            )

        if host_observations.get("ldap_highlights"):
            findings.append(
                Finding(
                    title="LDAP naming context information discovered",
                    severity="info",
                    category="windows",
                    description="LDAP base queries exposed one or more naming contexts or root DSE details.",
                    evidence=[str(item) for item in host_observations.get("ldap_highlights", [])[:4]],
                    follow_up="Correlate LDAP naming contexts with hostnames, AD indicators, and engagement scope.",
                )
            )

        if host_observations.get("snmp_highlights"):
            findings.append(
                Finding(
                    title="SNMP metadata exposed",
                    severity="info",
                    category="fingerprint",
                    description="SNMP enrichment returned one or more basic system-identifying values.",
                    evidence=[str(item) for item in host_observations.get("snmp_highlights", [])[:4]],
                    follow_up="Validate whether SNMP exposure is expected and whether the returned metadata matches the authorized environment.",
                )
            )

        if host_observations.get("rdp_highlights"):
            findings.append(
                Finding(
                    title="RDP service observations collected",
                    severity="info",
                    category="access",
                    description="RDP-aware checks returned one or more observations for the exposed service.",
                    evidence=[str(item) for item in host_observations.get("rdp_highlights", [])[:4]],
                    follow_up="Validate the exposed RDP service against management segmentation and hardening baselines.",
                )
            )

        if host_observations.get("ike_highlights"):
            findings.append(
                Finding(
                    title="IKE or VPN responder metadata captured",
                    severity="info",
                    category="access",
                    description="IKE-aware checks returned responder metadata for a VPN-style service.",
                    evidence=[str(item) for item in host_observations.get("ike_highlights", [])[:4]],
                    follow_up="Review the VPN exposure against approved remote-access architecture and expected responder identity.",
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

        deduped: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for finding in findings:
            marker = (finding.title, finding.description)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(finding)
        return deduped
