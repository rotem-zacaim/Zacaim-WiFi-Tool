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


class ToolInstaller:
    TOOL_PACKAGE_MAP = {
        "nmap": "nmap",
        "curl": "curl",
        "openssl": "openssl",
        "whatweb": "whatweb",
        "wafw00f": "wafw00f",
        "testssl.sh": "testssl.sh",
        "dig": "dnsutils",
        "host": "bind9-host",
        "ssh-keyscan": "openssh-client",
        "iw": "iw",
        "nmcli": "network-manager",
    }
    MANUAL_TOOL_NOTES = {
        "httpx": "Install manually from the ProjectDiscovery release or Go toolchain.",
        "katana": "Install manually from the ProjectDiscovery release or Go toolchain.",
    }

    @classmethod
    def assess_missing(cls, payload: dict[str, Any]) -> dict[str, Any]:
        tools = payload.get("tools", {})
        missing_tools = [tool for tool, location in tools.items() if not location]
        supported_tools: list[str] = []
        unsupported_tools: list[str] = []
        package_notes: dict[str, str] = {}
        packages: list[str] = []

        for tool in missing_tools:
            package = cls.TOOL_PACKAGE_MAP.get(tool)
            if package:
                supported_tools.append(tool)
                if package not in packages:
                    packages.append(package)
                package_notes[tool] = package
            else:
                unsupported_tools.append(tool)

        return {
            "missing_tools": missing_tools,
            "supported_tools": supported_tools,
            "unsupported_tools": unsupported_tools,
            "packages": packages,
            "package_notes": package_notes,
            "manual_notes": {
                tool: cls.MANUAL_TOOL_NOTES.get(tool, "Install manually for this environment.")
                for tool in unsupported_tools
            },
        }

    @classmethod
    def install_missing(cls, payload: dict[str, Any], assume_yes: bool = True) -> dict[str, Any]:
        if shutil.which("apt-get") is None:
            raise ValueError("Automatic installation currently supports apt-based systems only.")

        plan = cls.assess_missing(payload)
        packages = list(plan["packages"])
        if not packages:
            return {"changed": False, "packages": [], "reason": "No supported missing packages were found."}

        command_prefix = [] if is_root() else ["sudo"]
        if command_prefix and shutil.which("sudo") is None:
            raise ValueError("sudo is required to install missing packages from the interactive UI.")

        update_command = command_prefix + ["apt-get", "update"]
        install_command = command_prefix + ["apt-get", "install"]
        if assume_yes:
            install_command.append("-y")
        install_command.extend(packages)

        update_result = subprocess.run(update_command, check=False)
        if update_result.returncode != 0:
            raise RuntimeError("apt-get update failed.")

        install_result = subprocess.run(install_command, check=False)
        if install_result.returncode != 0:
            raise RuntimeError("apt-get install failed.")

        return {"changed": True, "packages": packages, "reason": "Installed supported missing packages."}


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
