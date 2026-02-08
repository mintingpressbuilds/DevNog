"""Undo/rollback support for applied fixes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from devnog.core.config import get_devnog_dir
from devnog.core.models import FixResult


@dataclass
class UndoEntry:
    """An undoable fix record."""

    finding_id: str
    file: Path
    backup: Path
    timestamp: str


class UndoManager:
    """Manages undo operations for applied fixes."""

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.devnog_dir = get_devnog_dir(project_path)
        self.backup_dir = self.devnog_dir / "backups"

    def list_undoable(self) -> list[UndoEntry]:
        """List all fixes that can be undone."""
        entries = []
        if not self.backup_dir.exists():
            return entries

        for session_dir in sorted(self.backup_dir.iterdir(), reverse=True):
            manifest_file = session_dir / "manifest.json"
            if manifest_file.exists():
                manifest = json.loads(manifest_file.read_text())
                for entry in manifest:
                    entries.append(UndoEntry(
                        finding_id=entry["finding_id"],
                        file=Path(entry["file"]),
                        backup=Path(entry["backup"]),
                        timestamp=entry["timestamp"],
                    ))

        return entries

    def undo(self, finding_id: str) -> FixResult:
        """Undo a specific fix by restoring the backup."""
        entries = self.list_undoable()

        for entry in entries:
            if entry.finding_id == finding_id:
                if not entry.backup.exists():
                    return FixResult(
                        success=False,
                        message=f"Backup file not found for {finding_id}",
                        finding_id=finding_id,
                    )

                backup_content = entry.backup.read_text()
                target_file = entry.file
                if not target_file.is_absolute():
                    target_file = self.project_path / target_file

                target_file.write_text(backup_content)

                return FixResult(
                    success=True,
                    message=f"Reverted {finding_id} — restored {entry.file}",
                    file=entry.file,
                    finding_id=finding_id,
                )

        return FixResult(
            success=False,
            message=f"No undo history for {finding_id}",
            finding_id=finding_id,
        )

    def undo_last_session(self) -> list[FixResult]:
        """Undo all fixes from the most recent fix session."""
        results = []
        if not self.backup_dir.exists():
            return results

        sessions = sorted(self.backup_dir.iterdir(), reverse=True)
        if not sessions:
            return results

        latest_session = sessions[0]
        manifest_file = latest_session / "manifest.json"
        if not manifest_file.exists():
            return results

        manifest = json.loads(manifest_file.read_text())
        for entry in manifest:
            result = self.undo(entry["finding_id"])
            results.append(result)

        return results
