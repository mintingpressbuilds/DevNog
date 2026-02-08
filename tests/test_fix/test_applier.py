"""Tests for fix application and backup."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def _make_proposal(
    file: Path,
    finding_id: str = "SEC-001",
    original_code: str = 'password = "secret"',
    new_code: str = 'password = os.environ["PASSWORD"]',
    line_start: int = 1,
    line_end: int = 1,
) -> FixProposal:
    return FixProposal(
        finding_id=finding_id,
        fix_type="rule_based",
        description="Test fix",
        diff=f"- {original_code}\n+ {new_code}",
        file=file,
        line_start=line_start,
        line_end=line_end,
        new_code=new_code,
        original_code=original_code,
        confidence="high",
        confidence_score=0.95,
    )


class TestFixApplier:
    def test_apply_replaces_code(self, applier: FixApplier, project: Path):
        """Applying a fix should replace the original code."""
        source_file = project / "app.py"
        source_file.write_text('password = "secret"\nother = True\n')

        proposal = _make_proposal(file=source_file)
        result = applier.apply(proposal)

        assert result.success is True
        content = source_file.read_text()
        assert 'os.environ["PASSWORD"]' in content
        assert '"secret"' not in content

    def test_apply_creates_backup(self, applier: FixApplier, project: Path):
        """Applying a fix should create a backup file."""
        source_file = project / "app.py"
        original = 'password = "secret"\n'
        source_file.write_text(original)

        proposal = _make_proposal(file=source_file)
        result = applier.apply(proposal)

        assert result.success is True

        # Check backup directory was created
        backup_dir = project / ".devnog" / "backups"
        assert backup_dir.exists()

        # Find backup files
        backup_files = list(backup_dir.rglob("*.bak"))
        assert len(backup_files) >= 1

        # Backup content should match original
        backup_content = backup_files[0].read_text()
        assert backup_content == original

    def test_apply_creates_manifest(self, applier: FixApplier, project: Path):
        """Applying a fix should create a manifest.json."""
        source_file = project / "app.py"
        source_file.write_text('password = "secret"\n')

        proposal = _make_proposal(file=source_file)
        applier.apply(proposal)

        manifest_files = list((project / ".devnog" / "backups").rglob("manifest.json"))
        assert len(manifest_files) >= 1

        manifest = json.loads(manifest_files[0].read_text())
        assert len(manifest) >= 1
        assert manifest[0]["finding_id"] == "SEC-001"

    def test_apply_fails_file_not_found(self, applier: FixApplier, project: Path):
        """Applying to a nonexistent file should fail gracefully."""
        proposal = _make_proposal(file=project / "nonexistent.py")
        result = applier.apply(proposal)

        assert result.success is False
        assert "not found" in result.message.lower()

    def test_apply_fails_changed_source(self, applier: FixApplier, project: Path):
        """If source has changed since scan, apply should fail."""
        source_file = project / "app.py"
        source_file.write_text("completely_different_code = True\n")

        proposal = _make_proposal(file=source_file)
        result = applier.apply(proposal)

        assert result.success is False
        assert "changed" in result.message.lower()

    def test_apply_removes_line(self, applier: FixApplier, project: Path):
        """Applying a fix with empty new_code should remove the line."""
        source_file = project / "app.py"
        source_file.write_text("import sys\nimport os\n\nprint(os.getcwd())\n")

        proposal = FixProposal(
            finding_id="CQ-004",
            fix_type="rule_based",
            description="Remove unused import",
            diff="- import sys",
            file=source_file,
            line_start=1,
            line_end=1,
            new_code="",
            original_code="import sys",
            confidence="high",
            confidence_score=0.90,
        )
        result = applier.apply(proposal)

        assert result.success is True
        content = source_file.read_text()
        assert "import sys" not in content
        assert "import os" in content

    def test_apply_multiple_fixes(self, applier: FixApplier, project: Path):
        """Multiple fixes should each create separate backups."""
        source_file = project / "app.py"
        source_file.write_text(
            'password = "secret"\n'
            'api_key = "abc123def456"\n'
        )

        proposal1 = _make_proposal(
            file=source_file,
            finding_id="SEC-001",
            original_code='password = "secret"',
            new_code='password = os.environ["PASSWORD"]',
        )
        result1 = applier.apply(proposal1)
        assert result1.success is True

        # Re-read and create second proposal
        proposal2 = _make_proposal(
            file=source_file,
            finding_id="SEC-001",
            original_code='api_key = "abc123def456"',
            new_code='api_key = os.environ["API_KEY"]',
            line_start=2,
            line_end=2,
        )
        result2 = applier.apply(proposal2)
        assert result2.success is True

    def test_apply_relative_path(self, applier: FixApplier, project: Path):
        """Applier should resolve relative paths against project_path."""
        source_file = project / "app.py"
        source_file.write_text('password = "secret"\n')

        proposal = _make_proposal(file=Path("app.py"))
        result = applier.apply(proposal)

        assert result.success is True
