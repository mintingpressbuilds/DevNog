"""Fix application and backup management."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from devnog.core.config import get_devnog_dir
from devnog.core.models import FixProposal, FixResult


class FixApplier:
    """Applies fixes to source files with backup support."""

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.devnog_dir = get_devnog_dir(project_path)
        self.backup_dir = self.devnog_dir / "backups"

    def apply(self, proposal: FixProposal) -> FixResult:
        """Apply a fix to the actual source file."""
        file_path = self._resolve_file(proposal.file)

        if not file_path.exists():
            return FixResult(
                success=False,
                message=f"File not found: {proposal.file}",
                finding_id=proposal.finding_id,
            )

        content = file_path.read_text()

        # Verify original code still matches
        if proposal.original_code and proposal.original_code.strip() not in content:
            return FixResult(
                success=False,
                message="Source file has changed since scan. Re-run `devnog scan` first.",
                finding_id=proposal.finding_id,
            )

        # Create backup
        self._create_backup(proposal.finding_id, file_path, content)

        # Apply the fix
        if proposal.new_code == "":
            # Removing a line (e.g., unused import)
            lines = content.splitlines(keepends=True)
            if proposal.line_start and proposal.line_start <= len(lines):
                del lines[proposal.line_start - 1]
                new_content = "".join(lines)
            else:
                new_content = content
        elif proposal.original_code:
            # Replace original code with new code
            new_content = content.replace(
                proposal.original_code.strip(), proposal.new_code.strip(), 1
            )
        else:
            new_content = content

        if new_content == content:
            return FixResult(
                success=False,
                message="No changes applied — original code not found in file.",
                finding_id=proposal.finding_id,
            )

        file_path.write_text(new_content)

        return FixResult(
            success=True,
            message=f"Fixed {proposal.finding_id}: {proposal.description}",
            file=proposal.file,
            lines_changed=abs(proposal.line_end - proposal.line_start) + 1 if proposal.line_end else 1,
            manual_steps=proposal.manual_steps,
            finding_id=proposal.finding_id,
        )

    def _resolve_file(self, file: Path) -> Path:
        """Resolve a possibly relative file path."""
        if file.is_absolute():
            return file
        return self.project_path / file

    def _create_backup(self, finding_id: str, file_path: Path, content: str) -> None:
        """Create a backup of the file before modifying it."""
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        backup_session = self.backup_dir / timestamp
        backup_session.mkdir(parents=True, exist_ok=True)

        # Save the original file
        backup_file = backup_session / f"{file_path.name}.bak"
        counter = 1
        while backup_file.exists():
            backup_file = backup_session / f"{file_path.name}.{counter}.bak"
            counter += 1
        backup_file.write_text(content)

        # Update manifest
        manifest_file = backup_session / "manifest.json"
        manifest = []
        if manifest_file.exists():
            manifest = json.loads(manifest_file.read_text())

        manifest.append({
            "finding_id": finding_id,
            "file": str(file_path),
            "backup": str(backup_file),
            "timestamp": timestamp,
        })
        manifest_file.write_text(json.dumps(manifest, indent=2))
