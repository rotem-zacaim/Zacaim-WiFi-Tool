"""Workspace/session management."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .filesystem import SESSIONS_DIR
from .validators import slugify


class WorkspaceManager:
    def create_session(self, target: str, profile: str, sessions_root: Path | None = None) -> Path:
        root = sessions_root or SESSIONS_DIR
        root.mkdir(parents=True, exist_ok=True)
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = slugify(target)
        session_dir = root / f"{session_id}_{target_slug}_{profile}"
        session_dir.mkdir(parents=True, exist_ok=True)
        for child in ["artifacts", "reports", "raw"]:
            (session_dir / child).mkdir(exist_ok=True)
        return session_dir
