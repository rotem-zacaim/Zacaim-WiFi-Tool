"""Health and local environment checks."""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from typing import Any

from .constants import APP_NAME
from .filesystem import CONFIG_FILE, ENGAGEMENTS_DIR, SESSIONS_DIR, ensure_app_dirs, write_json
from .validators import is_root


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
    def run(cls) -> dict[str, Any]:
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
    def run() -> dict[str, Any]:
        payload: dict[str, Any] = {
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
                check=False,
            )
            current: dict[str, str] = {}
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
                check=False,
            )
            states: dict[str, str] = {}
            for line in result.stdout.splitlines():
                device, device_type, state = (line.split(":", 2) + ["", "", ""])[:3]
                if device_type == "wifi":
                    states[device] = state
            for interface in payload["interfaces"]:
                interface["state"] = states.get(interface.get("name", ""), "unknown")

        return payload
