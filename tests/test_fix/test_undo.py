"""Tests for undo functionality."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from devnog.fix.undo import UndoManager, UndoEntry
from devnog.fix.applier import FixApplier
from devnog.core.models import FixProposal, FixResult


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """Create a minimal project directory."""
    (tmp_path / ".devnog").mkdir()
    return tmp_path


@pytest.fixture
def applier(project: Path) -> FixApplier:
    return FixApplier(project_path=project)


@pytest.fixture
def undo_mgr(project: Path) -> UndoManager:
    return UndoManager(project_path=project)


def _apply_fix(applier: FixApplier, project: Path, finding_id: str = "SEC-001") -> Path:
    """Helper: create a file, apply a fix, return the file path."""
    source_file = project / "app.py"
    source_file.write_text('password = "secret"\nother = True\n')

    proposal = FixProposal(
        finding_id=finding_id,
        fix_type="rule_based",
        description="Test fix",
        diff='- password = "secret"\n+ password = os.environ["PASSWORD"]',
        file=source_file,
        line_start=1,
        line_end=1,
        new_code='password = os.environ["PASSWORD"]',
        original_code='password = "secret"',
        confidence="high",
        confidence_score=0.95,
    )
    result = applier.apply(proposal)
    assert result.success is True
    return source_file


class TestUndoManager:
    def test_list_undoable_after_fix(
        self, applier: FixApplier, undo_mgr: UndoManager, project: Path
    ):
        """After applying a fix, list_undoable should return the entry."""
        _apply_fix(applier, project)

        entries = undo_mgr.list_undoable()
        assert len(entries) >= 1
        assert isinstance(entries[0], UndoEntry)
        assert entries[0].finding_id == "SEC-001"

    def test_list_undoable_empty(self, undo_mgr: UndoManager):
        """With no fixes applied, list_undoable should return empty."""
        entries = undo_mgr.list_undoable()
        assert len(entries) == 0

    def test_undo_restores_original(
        self, applier: FixApplier, undo_mgr: UndoManager, project: Path
    ):
        """Undoing a fix should restore the original file content."""
        source_file = _apply_fix(applier, project)

        # Verify fix was applied
        content_after_fix = source_file.read_text()
        assert "os.environ" in content_after_fix

        # Undo
        result = undo_mgr.undo("SEC-001")
        assert result.success is True

        # Verify original content is restored
        content_after_undo = source_file.read_text()
        assert 'password = "secret"' in content_after_undo

    def test_undo_nonexistent_finding(self, undo_mgr: UndoManager):
        """Undoing a finding that was never fixed should fail."""
        result = undo_mgr.undo("NONEXISTENT-999")
        assert result.success is False
        assert "no undo" in result.message.lower()

    def test_undo_last_session(
        self, applier: FixApplier, undo_mgr: UndoManager, project: Path
    ):
        """undo_last_session should revert all fixes from the last session."""
        source_file = _apply_fix(applier, project)

        results = undo_mgr.undo_last_session()
        assert len(results) >= 1
        assert all(r.success for r in results)

        content = source_file.read_text()
        assert 'password = "secret"' in content

    def test_undo_last_session_empty(self, undo_mgr: UndoManager):
        """undo_last_session with no history should return empty list."""
        results = undo_mgr.undo_last_session()
        assert len(results) == 0

    def test_undo_preserves_backup(
        self, applier: FixApplier, undo_mgr: UndoManager, project: Path
    ):
        """After undo, the backup file should still exist (for audit trail)."""
        _apply_fix(applier, project)

        backup_dir = project / ".devnog" / "backups"
        backup_files_before = list(backup_dir.rglob("*.bak"))
        assert len(backup_files_before) >= 1

        undo_mgr.undo("SEC-001")

        # Backup should still exist
        backup_files_after = list(backup_dir.rglob("*.bak"))
        assert len(backup_files_after) >= 1

    def test_undo_entry_fields(
        self, applier: FixApplier, undo_mgr: UndoManager, project: Path
    ):
        """UndoEntry should have all expected fields populated."""
        _apply_fix(applier, project)

        entries = undo_mgr.list_undoable()
        entry = entries[0]

        assert entry.finding_id == "SEC-001"
        assert entry.file is not None
        assert entry.backup is not None
        assert entry.timestamp != ""
