"""Filesystem helpers and application paths."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, List


def _writable_candidate(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".zacaim_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def resolve_app_dir(cwd: Path | None = None) -> Path:
    working_dir = (cwd or Path.cwd()).resolve()
    candidates: List[Path] = []

    custom_home = os.environ.get("ZACAIM_HOME")
    if custom_home:
        candidates.append(Path(custom_home).expanduser())

    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        candidates.append(Path(xdg_state_home).expanduser() / "zacaim_v2")

    candidates.append(working_dir / ".zacaim_v2")

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        candidates.append(Path(local_appdata) / "zacaim_v2")

    candidates.append(Path.home() / ".zacaim_v2")

    for candidate in candidates:
        if _writable_candidate(candidate):
            return candidate

    raise PermissionError("Unable to create a writable application data directory for ZACAIM.")


APP_DIR = resolve_app_dir()
SESSIONS_DIR = APP_DIR / "sessions"
ENGAGEMENTS_DIR = APP_DIR / "engagements"
CONFIG_FILE = APP_DIR / "config.json"


def ensure_app_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
