"""Tests for the Scanner engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.scanner.engine import Scanner
from devnog.core.config import DevNogConfig, ScanConfig
from devnog.core.models import Category, Finding, Severity, ScanReport


@pytest.fixture
def sample_project(tmp_path: Path) -> Path:
    """Create a minimal project for scanning."""
    # A file with known issues
    code = '''\
import os
import sys  # unused

password = "super-secret-123"
DEBUG = True

def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return query

def process():
    try:
        risky()
    except:
        pass
'''
    (tmp_path / "app.py").write_text(code)
    return tmp_path


@pytest.fixture
def clean_project(tmp_path: Path) -> Path:
    """Create a project with no issues."""
    code = '''\
"""A clean module."""
import os


def greet(name: str) -> str:
    """Greet someone by name."""
    return f"Hello, {name}!"
'''
    (tmp_path / "clean.py").write_text(code)
    return tmp_path


class TestScanner:
    def test_scan_finds_issues(self, sample_project: Path):
        """Scanner should detect issues in sample project."""
        config = DevNogConfig()
        scanner = Scanner(project_path=sample_project, config=config)
        report = scanner.scan()

        assert isinstance(report, ScanReport)
        assert len(report.findings) > 0
        assert report.total_files >= 1
        assert report.total_lines > 0

    def test_scan_reports_check_ids(self, sample_project: Path):
        """Findings should have valid check_id values."""
        config = DevNogConfig()
        scanner = Scanner(project_path=sample_project, config=config)
        report = scanner.scan()

        check_ids = {f.check_id for f in report.findings}
        # We expect at least some of these known issues
        # SEC-001 (hardcoded password), SEC-006 (DEBUG=True),
        # SEC-002 (SQL injection), ERR-001 (bare except), ERR-002 (except pass)
        assert "SEC-001" in check_ids or "SEC-006" in check_ids or "ERR-001" in check_ids

    def test_scan_computes_scores(self, sample_project: Path):
        """Scanner should compute valid scores."""
        config = DevNogConfig()
        scanner = Scanner(project_path=sample_project, config=config)
        report = scanner.scan()

        assert 0 <= report.overall_score <= 100
        for key, cat_score in report.category_scores.items():
            assert 0 <= cat_score.score <= 100

    def test_scan_clean_project(self, clean_project: Path):
        """A clean project should score high with few/no critical findings."""
        config = DevNogConfig()
        scanner = Scanner(project_path=clean_project, config=config)
        report = scanner.scan()

        assert report.overall_score >= 70
        assert report.critical_count == 0

    def test_scan_with_ignore(self, sample_project: Path):
        """Ignored checks should not appear in findings."""
        config = DevNogConfig(
            scan=ScanConfig(ignore=["SEC-001", "SEC-006", "SEC-002"])
        )
        scanner = Scanner(project_path=sample_project, config=config)
        report = scanner.scan()

        check_ids = {f.check_id for f in report.findings}
        assert "SEC-001" not in check_ids
        assert "SEC-006" not in check_ids
        assert "SEC-002" not in check_ids

    def test_scan_category_filter(self, sample_project: Path):
        """Filtering categories should exclude those check categories."""
        config = DevNogConfig(
            scan=ScanConfig(categories=["code_quality"])
        )
        scanner = Scanner(project_path=sample_project, config=config)
        report = scanner.scan()

        # Should only have code_quality findings
        for finding in report.findings:
            assert finding.category == Category.CODE_QUALITY

    def test_scan_empty_directory(self, tmp_path: Path):
        """Scanning an empty directory should produce no AST-based findings."""
        config = DevNogConfig()
        # Disable dependency checks that query system-level state
        config.scan.categories = ["code_quality", "security", "error_handling"]
        scanner = Scanner(project_path=tmp_path, config=config)
        report = scanner.scan()

        assert len(report.findings) == 0
        assert report.total_files == 0

    def test_scan_single_file(self, tmp_path: Path):
        """Scanner should handle scanning a single file."""
        code = 'password = "secret-value-here"\n'
        f = tmp_path / "single.py"
        f.write_text(code)

        config = DevNogConfig()
        scanner = Scanner(project_path=tmp_path, config=config)
        report = scanner.scan()

        assert report.total_files >= 1
        assert len(report.findings) >= 1

    def test_scan_syntax_error_file(self, tmp_path: Path):
        """Scanner should not crash on files with syntax errors."""
        (tmp_path / "bad_syntax.py").write_text("def foo(\n")
        (tmp_path / "good.py").write_text("x = 1\n")

        config = DevNogConfig()
        scanner = Scanner(project_path=tmp_path, config=config)
        report = scanner.scan()

        # Should still scan the good file without crashing
        assert report.total_files >= 1

    def test_scan_excludes_directories(self, tmp_path: Path):
        """Scanner should respect exclude patterns."""
        venv = tmp_path / "venv"
        venv.mkdir()
        (venv / "lib.py").write_text('password = "bad"\n')
        (tmp_path / "app.py").write_text("x = 1\n")

        config = DevNogConfig(exclude=["venv/"])
        scanner = Scanner(project_path=tmp_path, config=config)
        report = scanner.scan()

        # venv/lib.py should be excluded
        files_scanned = {f.file for f in report.findings if f.file}
        for f in files_scanned:
            assert "venv" not in str(f)

    def test_scan_report_properties(self, sample_project: Path):
        """ScanReport properties should work correctly."""
        config = DevNogConfig()
        scanner = Scanner(project_path=sample_project, config=config)
        report = scanner.scan()

        # These should not raise
        _ = report.critical_count
        _ = report.warning_count
        _ = report.info_count
        _ = report.auto_fixable_count
        _ = report.ai_fixable_count
        _ = report.manual_count

        # Counts should sum to total
        total = report.critical_count + report.warning_count + report.info_count
        assert total == len(report.findings)
