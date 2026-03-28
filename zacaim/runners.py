"""Command execution helpers."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from .filesystem import write_text
from .models import CommandResult


class CommandRunner:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def tool_available(self, name: str) -> bool:
        return shutil.which(name) is not None

    def run(
        self,
        name: str,
        command: list[str],
        artifact_prefix: str,
        timeout: int = 1800,
        required_tool: str | None = None,
    ) -> CommandResult:
        required = required_tool or command[0]
        stdout_path = self.base_dir / "artifacts" / f"{artifact_prefix}.stdout.txt"
        stderr_path = self.base_dir / "artifacts" / f"{artifact_prefix}.stderr.txt"

        if not self.tool_available(required):
            message = f"Skipped: required tool '{required}' is not installed."
            write_text(stdout_path, "")
            write_text(stderr_path, message)
            return CommandResult(
                name=name,
                command=command,
                returncode=None,
                duration_seconds=0.0,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                skipped=True,
                reason=message,
            )

        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
            started_at = time.time()
            try:
                completed = subprocess.run(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=False,
                )
                return CommandResult(
                    name=name,
                    command=command,
                    returncode=completed.returncode,
                    duration_seconds=time.time() - started_at,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                )
            except subprocess.TimeoutExpired:
                stderr_file.write(f"Timed out after {timeout} seconds.\n")
                return CommandResult(
                    name=name,
                    command=command,
                    returncode=None,
                    duration_seconds=time.time() - started_at,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                    skipped=True,
                    reason=f"Timed out after {timeout} seconds.",
                )
