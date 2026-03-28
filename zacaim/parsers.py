"""Output parsers."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin
from xml.etree import ElementTree as ET

from .models import ServiceFinding


class NmapParser:
    @staticmethod
    def parse(xml_path: Path) -> dict[str, object]:
        result: dict[str, object] = {"services": [], "os_guess": ""}
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

        services: list[ServiceFinding] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            service = port.find("service")
            services.append(
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

        result["services"] = services
        return result


def parse_robots_txt(content: str, source_url: str = "") -> dict[str, object]:
    groups: list[dict[str, object]] = []
    current_group: dict[str, object] | None = None
    global_sitemaps: list[str] = []
    host = ""
    all_user_agents: list[str] = []
    interesting_urls: list[str] = []
    interesting_paths: list[str] = []

    def ensure_group() -> dict[str, object]:
        nonlocal current_group
        if current_group is None:
            current_group = {
                "user_agents": [],
                "allow": [],
                "disallow": [],
                "crawl_delay": "",
            }
            groups.append(current_group)
        return current_group

    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        field, value = [part.strip() for part in line.split(":", 1)]
        field = field.lower()
        if not value:
            continue

        if field == "user-agent":
            if current_group and (
                current_group.get("allow")
                or current_group.get("disallow")
                or current_group.get("crawl_delay")
            ):
                current_group = None
            group = ensure_group()
            user_agents = group["user_agents"]
            if value not in user_agents:
                user_agents.append(value)
            if value not in all_user_agents:
                all_user_agents.append(value)
            continue

        if field == "allow":
            group = ensure_group()
            group["allow"].append(value)
            if value not in interesting_paths:
                interesting_paths.append(value)
            if source_url:
                absolute_url = urljoin(source_url, value)
                if absolute_url not in interesting_urls:
                    interesting_urls.append(absolute_url)
            continue

        if field == "disallow":
            group = ensure_group()
            group["disallow"].append(value)
            if value not in interesting_paths:
                interesting_paths.append(value)
            if source_url:
                absolute_url = urljoin(source_url, value)
                if absolute_url not in interesting_urls:
                    interesting_urls.append(absolute_url)
            continue

        if field == "crawl-delay":
            group = ensure_group()
            group["crawl_delay"] = value
            continue

        if field == "host":
            host = value
            continue

        if field == "sitemap":
            if value not in global_sitemaps:
                global_sitemaps.append(value)
            if value not in interesting_urls:
                interesting_urls.append(value)

    allow_count = sum(len(group["allow"]) for group in groups)
    disallow_count = sum(len(group["disallow"]) for group in groups)
    return {
        "url": source_url,
        "group_count": len(groups),
        "user_agents": all_user_agents,
        "allow_count": allow_count,
        "disallow_count": disallow_count,
        "host": host,
        "sitemaps": global_sitemaps,
        "interesting_paths": interesting_paths[:25],
        "interesting_urls": interesting_urls[:25],
        "groups": groups[:8],
    }


def parse_sitemap_xml(content: str, source_url: str = "") -> dict[str, object]:
    result: dict[str, object] = {
        "url": source_url,
        "kind": "invalid",
        "url_count": 0,
        "sample_urls": [],
        "child_sitemaps": [],
        "lastmod_count": 0,
    }
    if not content.strip():
        return result

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return result

    tag = root.tag.split("}", 1)[-1].lower()
    if tag == "urlset":
        urls: list[str] = []
        lastmod_count = 0
        for url_element in root.findall(".//{*}url"):
            loc = url_element.findtext("{*}loc", default="").strip()
            if loc and loc not in urls:
                urls.append(loc)
            if url_element.findtext("{*}lastmod", default="").strip():
                lastmod_count += 1
        result["kind"] = "urlset"
        result["url_count"] = len(urls)
        result["sample_urls"] = urls[:25]
        result["lastmod_count"] = lastmod_count
        return result

    if tag == "sitemapindex":
        children: list[str] = []
        lastmod_count = 0
        for sitemap_element in root.findall(".//{*}sitemap"):
            loc = sitemap_element.findtext("{*}loc", default="").strip()
            if loc and loc not in children:
                children.append(loc)
            if sitemap_element.findtext("{*}lastmod", default="").strip():
                lastmod_count += 1
        result["kind"] = "sitemapindex"
        result["url_count"] = len(children)
        result["child_sitemaps"] = children[:25]
        result["lastmod_count"] = lastmod_count
        return result

    return result


def parse_security_txt(content: str, source_url: str = "") -> dict[str, object]:
    fields: dict[str, list[str]] = {}
    interesting_contacts: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        field, value = [part.strip() for part in line.split(":", 1)]
        field_key = field.lower()
        fields.setdefault(field_key, [])
        if value and value not in fields[field_key]:
            fields[field_key].append(value)
        if field_key == "contact" and value and value not in interesting_contacts:
            interesting_contacts.append(value)

    return {
        "url": source_url,
        "fields": fields,
        "field_count": len(fields),
        "contact_count": len(fields.get("contact", [])),
        "contacts": interesting_contacts[:10],
        "encryption": fields.get("encryption", [])[:5],
        "policy": fields.get("policy", [])[:5],
    }
