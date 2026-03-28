"""Engagement registry and evidence handling."""

from __future__ import annotations

import shutil
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .filesystem import ENGAGEMENTS_DIR, ensure_app_dirs, read_json, write_json, write_text
from .models import TargetSummary
from .validators import TargetValidator, now_iso, slugify


class EngagementManager:
    def __init__(self) -> None:
        ensure_app_dirs()

    def create(self, name: str, description: str = "", scope: str = "") -> dict[str, str]:
        engagement_id = slugify(name)
        engagement_dir = ENGAGEMENTS_DIR / engagement_id
        if engagement_dir.exists():
            raise ValueError(f"Engagement '{engagement_id}' already exists.")

        for child in ["targets", "sessions", "reports"]:
            (engagement_dir / child).mkdir(parents=True, exist_ok=True)

        metadata = {
            "id": engagement_id,
            "name": name,
            "description": description,
            "scope": scope,
            "created_at": now_iso(),
        }
        write_json(engagement_dir / "engagement.json", metadata)
        write_json(engagement_dir / "targets.json", [])
        return metadata

    def list_engagements(self) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for path in sorted(ENGAGEMENTS_DIR.iterdir()) if ENGAGEMENTS_DIR.exists() else []:
            metadata = read_json(path / "engagement.json", {})
            if metadata:
                results.append(metadata)
        return results

    def get_engagement_dir(self, engagement_id: str) -> Path:
        path = ENGAGEMENTS_DIR / slugify(engagement_id)
        if not path.exists():
            raise ValueError(f"Engagement '{engagement_id}' does not exist.")
        return path

    def load_metadata(self, engagement_id: str) -> dict[str, str]:
        engagement_dir = self.get_engagement_dir(engagement_id)
        metadata = read_json(engagement_dir / "engagement.json", {})
        if not metadata:
            raise ValueError(f"Engagement '{engagement_id}' is missing metadata.")
        return metadata

    def load_targets(self, engagement_id: str) -> list[dict[str, object]]:
        engagement_dir = self.get_engagement_dir(engagement_id)
        return read_json(engagement_dir / "targets.json", [])

    def save_targets(self, engagement_id: str, targets: list[dict[str, object]]) -> None:
        engagement_dir = self.get_engagement_dir(engagement_id)
        write_json(engagement_dir / "targets.json", targets)

    def add_target(
        self,
        engagement_id: str,
        address: str,
        name: str = "",
        tags: list[str] | None = None,
    ) -> dict[str, object]:
        tags = tags or []
        targets = self.load_targets(engagement_id)
        normalized = TargetValidator.normalize(address)

        for target in targets:
            if target["address"] == normalized:
                raise ValueError(f"Target '{normalized}' already exists in this engagement.")

        base_id = slugify(name or normalized)
        target_id = base_id
        counter = 2
        existing_ids = {str(target["target_id"]) for target in targets}
        while target_id in existing_ids:
            target_id = f"{base_id}_{counter}"
            counter += 1

        engagement_dir = self.get_engagement_dir(engagement_id)
        target_dir = engagement_dir / "targets" / target_id
        for child in ["notes", "evidence", "reports"]:
            (target_dir / child).mkdir(parents=True, exist_ok=True)

        target_record: dict[str, object] = {
            "target_id": target_id,
            "name": name or normalized,
            "address": normalized,
            "kind": TargetValidator.kind(normalized),
            "tags": tags,
            "created_at": now_iso(),
            "note_count": 0,
            "evidence_count": 0,
            "last_scan_at": "",
            "last_profile": "",
            "last_session": "",
            "service_count": 0,
            "http_count": 0,
            "findings_count": 0,
            "os_guess": "",
        }

        write_json(target_dir / "notes" / "notes.json", [])
        write_json(target_dir / "evidence" / "evidence.json", [])
        targets.append(target_record)
        self.save_targets(engagement_id, targets)
        return target_record

    def resolve_target(self, engagement_id: str, identifier: str) -> dict[str, object]:
        targets = self.load_targets(engagement_id)
        normalized = identifier.strip()
        for target in targets:
            if normalized in {target["target_id"], target["address"], target["name"]}:
                return target
        raise ValueError(f"Target '{identifier}' was not found in engagement '{engagement_id}'.")

    def add_note(
        self,
        engagement_id: str,
        target_ref: str,
        text: str,
        category: str = "note",
        tags: list[str] | None = None,
    ) -> dict[str, object]:
        tags = tags or []
        target = self.resolve_target(engagement_id, target_ref)
        target_dir = self.get_engagement_dir(engagement_id) / "targets" / str(target["target_id"])
        notes_path = target_dir / "notes" / "notes.json"
        notes = read_json(notes_path, [])
        entry = {
            "id": f"note_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "created_at": now_iso(),
            "category": category,
            "tags": tags,
            "text": text,
        }
        notes.append(entry)
        write_json(notes_path, notes)
        self._update_target_counter(engagement_id, str(target["target_id"]), "note_count", len(notes))
        return entry

    def add_evidence(
        self,
        engagement_id: str,
        target_ref: str,
        description: str = "",
        text: str = "",
        file_path: str = "",
    ) -> dict[str, object]:
        if not text and not file_path:
            raise ValueError("Provide either evidence text or a file path.")

        target = self.resolve_target(engagement_id, target_ref)
        target_dir = self.get_engagement_dir(engagement_id) / "targets" / str(target["target_id"])
        evidence_dir = target_dir / "evidence"
        evidence_index_path = evidence_dir / "evidence.json"
        evidence_entries = read_json(evidence_index_path, [])
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        entry: dict[str, object] = {
            "id": f"evidence_{stamp}",
            "created_at": now_iso(),
            "description": description,
            "type": "text" if text else "file",
        }

        if text:
            stored_file = evidence_dir / f"{stamp}_note.txt"
            write_text(stored_file, text)
            entry["stored_path"] = str(stored_file)

        if file_path:
            source = Path(file_path).expanduser()
            if not source.exists() or not source.is_file():
                raise ValueError(f"Evidence file '{file_path}' was not found.")
            destination = evidence_dir / f"{stamp}_{source.name}"
            shutil.copy2(source, destination)
            entry["source_path"] = str(source)
            entry["stored_path"] = str(destination)

        evidence_entries.append(entry)
        write_json(evidence_index_path, evidence_entries)
        self._update_target_counter(engagement_id, str(target["target_id"]), "evidence_count", len(evidence_entries))
        return entry

    def update_target_after_scan(
        self,
        engagement_id: str,
        target_id: str,
        summary: TargetSummary,
        reports: dict[str, str],
    ) -> None:
        targets = self.load_targets(engagement_id)
        for target in targets:
            if target["target_id"] != target_id:
                continue
            target["last_scan_at"] = summary.started_at
            target["last_profile"] = summary.profile
            target["last_session"] = summary.session_id
            target["service_count"] = len(summary.open_services)
            target["http_count"] = len(summary.http_endpoints)
            target["findings_count"] = len(summary.findings)
            target["os_guess"] = summary.os_guess
            break
        self.save_targets(engagement_id, targets)

        target_dir = self.get_engagement_dir(engagement_id) / "targets" / target_id / "reports"
        write_json(target_dir / "latest_summary.json", asdict(summary))
        write_json(target_dir / "latest_findings.json", [asdict(finding) for finding in summary.findings])
        report_text = Path(reports["report_md"]).read_text(encoding="utf-8", errors="replace")
        write_text(target_dir / "latest_report.md", report_text)

    def _update_target_counter(self, engagement_id: str, target_id: str, field_name: str, value: int) -> None:
        targets = self.load_targets(engagement_id)
        for target in targets:
            if target["target_id"] == target_id:
                target[field_name] = value
                break
        self.save_targets(engagement_id, targets)
