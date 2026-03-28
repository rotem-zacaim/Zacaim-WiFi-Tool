"""Validation and normalization helpers."""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "item"


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


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
