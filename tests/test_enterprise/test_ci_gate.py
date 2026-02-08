"""Tests for CIScanDiff: comparing scans, generating PR comments, scan history storage."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devnog.core.models import Category, Finding, ScanReport, Severity
from devnog.enterprise.ci_gate import CIScanDiff, ScanDiff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    check_id: str = "SEC-001",
    category: Category = Category.SECURITY,
    severity: Severity = Severity.WARNING,
    message: str = "Test finding",
    file: str = "app.py",
    line: int = 10,
) -> Finding:
    """Create a Finding with sensible defaults."""
    return Finding(
        check_id=check_id,
        category=category,
        severity=severity,
        message=message,
        file=Path(file),
        line=line,
    )


def _report(
    score: int = 80,
    findings: list[Finding] | None = None,
    total_lines: int = 1000,
    total_files: int = 10,
) -> ScanReport:
    """Create a ScanReport for testing."""
    return ScanReport(
        overall_score=score,
        findings=findings or [],
        total_lines=total_lines,
        total_files=total_files,
    )


def _mock_subprocess_run(*args, **kwargs):
    """Mock subprocess.run that returns an object with a .stdout attribute."""
    result = MagicMock()
    result.stdout = ""
    return result


# ---------------------------------------------------------------------------
# diff()
# ---------------------------------------------------------------------------

class TestCIScanDiffDiff:
    """Tests for CIScanDiff.diff() — comparing two scans."""

    def test_diff_no_changes(self, tmp_path: Path):
        """Two identical scans should produce no new/resolved issues."""
        f1 = _finding(check_id="SEC-001", file="a.py", line=5)
        prev = _report(score=80, findings=[f1])
        curr = _report(score=80, findings=[f1])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.new_issues == []
        assert result.resolved_issues == []
        assert len(result.unchanged_issues) == 1
        assert result.score_delta == 0
        assert result.verdict == "pass"

    def test_diff_new_issues_detected(self, tmp_path: Path):
        """New findings in current scan should appear in new_issues."""
        f_old = _finding(check_id="SEC-001", file="a.py", line=5)
        f_new = _finding(check_id="SEC-002", file="b.py", line=10)
        prev = _report(score=85, findings=[f_old])
        curr = _report(score=75, findings=[f_old, f_new])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert len(result.new_issues) == 1
        assert result.new_issues[0].check_id == "SEC-002"
        assert len(result.unchanged_issues) == 1
        assert result.resolved_issues == []

    def test_diff_resolved_issues_detected(self, tmp_path: Path):
        """Findings removed in current scan should appear in resolved_issues."""
        f1 = _finding(check_id="SEC-001", file="a.py", line=5)
        f2 = _finding(check_id="SEC-002", file="b.py", line=10)
        prev = _report(score=70, findings=[f1, f2])
        curr = _report(score=85, findings=[f1])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.new_issues == []
        assert len(result.resolved_issues) == 1
        assert result.resolved_issues[0].check_id == "SEC-002"
        assert len(result.unchanged_issues) == 1

    def test_diff_score_delta_positive(self, tmp_path: Path):
        """Score improvement should produce a positive delta."""
        prev = _report(score=60, findings=[])
        curr = _report(score=80, findings=[])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.previous_score == 60
        assert result.current_score == 80
        assert result.score_delta == 20

    def test_diff_score_delta_negative(self, tmp_path: Path):
        """Score regression should produce a negative delta."""
        prev = _report(score=90, findings=[])
        curr = _report(score=70, findings=[])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.score_delta == -20

    def test_diff_verdict_pass_no_new_issues(self, tmp_path: Path):
        """Verdict should be 'pass' when no new issues exist."""
        prev = _report(score=80, findings=[])
        curr = _report(score=82, findings=[])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "pass"

    def test_diff_verdict_blocked_new_critical(self, tmp_path: Path):
        """Verdict should be 'blocked' when new CRITICAL issues appear."""
        f_critical = _finding(
            check_id="SEC-010",
            severity=Severity.CRITICAL,
            file="c.py",
            line=1,
        )
        prev = _report(score=90, findings=[])
        curr = _report(score=85, findings=[f_critical])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "blocked"
        assert len(result.new_issues) == 1

    def test_diff_verdict_warning_new_warning_issue(self, tmp_path: Path):
        """Verdict should be 'warning' when new WARNING issues appear (no criticals)."""
        f_warning = _finding(
            check_id="QA-010",
            severity=Severity.WARNING,
            file="d.py",
            line=5,
        )
        prev = _report(score=90, findings=[])
        curr = _report(score=88, findings=[f_warning])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "warning"

    def test_diff_verdict_warning_large_score_drop(self, tmp_path: Path):
        """Verdict should be 'warning' when score drops by more than 5 (no new issues)."""
        prev = _report(score=90, findings=[])
        curr = _report(score=80, findings=[])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "warning"

    def test_diff_verdict_pass_small_score_drop_info_issues(self, tmp_path: Path):
        """Verdict should be 'pass' for small score drop with only INFO issues."""
        f_info = _finding(
            check_id="QA-001",
            severity=Severity.INFO,
            file="e.py",
            line=2,
        )
        prev = _report(score=90, findings=[])
        curr = _report(score=88, findings=[f_info])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "pass"

    def test_diff_critical_overrides_score_drop(self, tmp_path: Path):
        """New critical should produce 'blocked' even if score improved."""
        f_critical = _finding(
            check_id="SEC-099",
            severity=Severity.CRITICAL,
            file="f.py",
            line=1,
        )
        prev = _report(score=70, findings=[])
        curr = _report(score=75, findings=[f_critical])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "blocked"

    def test_diff_empty_scans(self, tmp_path: Path):
        """Two empty scans should produce a clean pass."""
        prev = _report(score=100, findings=[])
        curr = _report(score=100, findings=[])

        ci = CIScanDiff(tmp_path)
        result = ci.diff(curr, prev)

        assert result.verdict == "pass"
        assert result.new_issues == []
        assert result.resolved_issues == []
        assert result.unchanged_issues == []
        assert result.score_delta == 0


# ---------------------------------------------------------------------------
# format_ci_output()
# ---------------------------------------------------------------------------

class TestCIScanDiffFormatCIOutput:
    """Tests for CIScanDiff.format_ci_output()."""

    def test_format_pass(self, tmp_path: Path):
        """Passing diff should show PASSED verdict."""
        diff = ScanDiff(
            previous_score=80,
            current_score=85,
            score_delta=5,
            verdict="pass",
        )
        ci = CIScanDiff(tmp_path)
        output = ci.format_ci_output(diff)

        assert "DevNog CI Scan Diff" in output
        assert "80 -> 85 (+5)" in output
        assert "PASSED" in output

    def test_format_blocked(self, tmp_path: Path):
        """Blocked diff should show BLOCKED verdict."""
        f = _finding(check_id="SEC-010", severity=Severity.CRITICAL)
        diff = ScanDiff(
            previous_score=90,
            current_score=75,
            score_delta=-15,
            new_issues=[f],
            verdict="blocked",
        )
        ci = CIScanDiff(tmp_path)
        output = ci.format_ci_output(diff)

        assert "BLOCKED" in output
        assert "CRITICAL" in output
        assert "SEC-010" in output

    def test_format_warning(self, tmp_path: Path):
        """Warning diff should show WARNING verdict."""
        f = _finding(check_id="QA-005", severity=Severity.WARNING)
        diff = ScanDiff(
            previous_score=85,
            current_score=82,
            score_delta=-3,
            new_issues=[f],
            verdict="warning",
        )
        ci = CIScanDiff(tmp_path)
        output = ci.format_ci_output(diff)

        assert "WARNING" in output
        assert "QA-005" in output

    def test_format_includes_resolved(self, tmp_path: Path):
        """Resolved issues should appear in the output."""
        f_resolved = _finding(check_id="SEC-003", message="hardcoded secret")
        diff = ScanDiff(
            previous_score=70,
            current_score=85,
            score_delta=15,
            resolved_issues=[f_resolved],
            verdict="pass",
        )
        ci = CIScanDiff(tmp_path)
        output = ci.format_ci_output(diff)

        assert "FIXED" in output
        assert "SEC-003" in output
        assert "hardcoded secret" in output

    def test_format_no_issues(self, tmp_path: Path):
        """A clean diff should not contain issue sections."""
        diff = ScanDiff(
            previous_score=90,
            current_score=92,
            score_delta=2,
            verdict="pass",
        )
        ci = CIScanDiff(tmp_path)
        output = ci.format_ci_output(diff)

        assert "New issues" not in output
        assert "Issues resolved" not in output
        assert "PASSED" in output


# ---------------------------------------------------------------------------
# generate_pr_comment()
# ---------------------------------------------------------------------------

class TestCIScanDiffPRComment:
    """Tests for CIScanDiff.generate_pr_comment()."""

    def test_pr_comment_pass(self, tmp_path: Path):
        """Passing PR comment should use white_check_mark icon."""
        diff = ScanDiff(
            previous_score=80,
            current_score=85,
            score_delta=5,
            verdict="pass",
        )
        ci = CIScanDiff(tmp_path)
        comment = ci.generate_pr_comment(diff)

        assert ":white_check_mark:" in comment
        assert "80 -> 85 (+5)" in comment
        assert "## DevNog Scan Diff" in comment

    def test_pr_comment_blocked(self, tmp_path: Path):
        """Blocked PR comment should use :x: icon and list critical issues."""
        f = _finding(
            check_id="SEC-010",
            severity=Severity.CRITICAL,
            message="SQL injection",
            file="db.py",
            line=42,
        )
        diff = ScanDiff(
            previous_score=85,
            current_score=70,
            score_delta=-15,
            new_issues=[f],
            verdict="blocked",
        )
        ci = CIScanDiff(tmp_path)
        comment = ci.generate_pr_comment(diff)

        assert ":x:" in comment
        assert "### New Issues" in comment
        assert ":red_circle:" in comment
        assert "SEC-010" in comment
        assert "SQL injection" in comment
        assert "`db.py:42`" in comment

    def test_pr_comment_warning(self, tmp_path: Path):
        """Warning PR comment should use :warning: icon."""
        f = _finding(
            check_id="QA-005",
            severity=Severity.WARNING,
            message="missing docstring",
        )
        diff = ScanDiff(
            previous_score=88,
            current_score=84,
            score_delta=-4,
            new_issues=[f],
            verdict="warning",
        )
        ci = CIScanDiff(tmp_path)
        comment = ci.generate_pr_comment(diff)

        assert ":warning:" in comment
        assert ":yellow_circle:" in comment

    def test_pr_comment_resolved_section(self, tmp_path: Path):
        """Resolved findings should appear under '### Resolved' section."""
        f = _finding(check_id="SEC-001", message="hardcoded password")
        diff = ScanDiff(
            previous_score=70,
            current_score=80,
            score_delta=10,
            resolved_issues=[f],
            verdict="pass",
        )
        ci = CIScanDiff(tmp_path)
        comment = ci.generate_pr_comment(diff)

        assert "### Resolved" in comment
        assert ":white_check_mark:" in comment
        assert "SEC-001" in comment

    def test_pr_comment_is_valid_markdown(self, tmp_path: Path):
        """PR comment should start with a Markdown heading."""
        diff = ScanDiff(
            previous_score=80,
            current_score=80,
            score_delta=0,
            verdict="pass",
        )
        ci = CIScanDiff(tmp_path)
        comment = ci.generate_pr_comment(diff)

        assert comment.startswith("## ")


# ---------------------------------------------------------------------------
# save_scan() / load_previous()
# ---------------------------------------------------------------------------

class TestCIScanDiffHistory:
    """Tests for CIScanDiff.save_scan() and load_previous()."""

    def test_save_and_load_roundtrip(self, tmp_path: Path):
        """save_scan() then load_previous() should recover the scan data."""
        findings = [
            _finding(check_id="SEC-001", severity=Severity.CRITICAL, file="a.py", line=1),
            _finding(check_id="QA-002", severity=Severity.WARNING, file="b.py", line=5),
        ]
        report = _report(score=72, findings=findings)

        ci = CIScanDiff(tmp_path)
        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            ci.save_scan(report)

        loaded = ci.load_previous()

        assert loaded is not None
        assert loaded.overall_score == 72
        assert len(loaded.findings) == 2
        assert loaded.findings[0].check_id == "SEC-001"
        assert loaded.findings[1].check_id == "QA-002"

    def test_save_creates_database_file(self, tmp_path: Path):
        """save_scan() should create history.db in .devnog directory."""
        report = _report(score=90, findings=[])
        ci = CIScanDiff(tmp_path)

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            ci.save_scan(report)

        db_path = tmp_path / ".devnog" / "history.db"
        assert db_path.exists()

    def test_save_multiple_load_returns_latest(self, tmp_path: Path):
        """After multiple saves, load_previous() should return the most recent."""
        ci = CIScanDiff(tmp_path)

        report1 = _report(score=60, findings=[])
        report2 = _report(score=75, findings=[])
        report3 = _report(score=90, findings=[])

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            ci.save_scan(report1)
            ci.save_scan(report2)
            ci.save_scan(report3)

        loaded = ci.load_previous()
        assert loaded is not None
        assert loaded.overall_score == 90

    def test_load_previous_no_database(self, tmp_path: Path):
        """load_previous() should return None when no database exists."""
        ci = CIScanDiff(tmp_path)
        # Ensure the .devnog dir exists but no db file
        (tmp_path / ".devnog").mkdir(exist_ok=True)
        assert ci.load_previous() is None

    def test_load_previous_empty_database(self, tmp_path: Path):
        """load_previous() should return None when database is empty."""
        ci = CIScanDiff(tmp_path)
        # Create db with table but no rows
        db_path = tmp_path / ".devnog" / "history.db"
        (tmp_path / ".devnog").mkdir(exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TIMESTAMP NOT NULL,
                overall_score INTEGER NOT NULL,
                findings_json TEXT
            )
        """)
        conn.commit()
        conn.close()

        assert ci.load_previous() is None

    def test_save_stores_finding_details(self, tmp_path: Path):
        """Saved findings should preserve check_id, severity, category, message."""
        f = _finding(
            check_id="SEC-005",
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            message="Debug mode enabled",
            file="settings.py",
            line=99,
        )
        report = _report(score=65, findings=[f])
        ci = CIScanDiff(tmp_path)

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            ci.save_scan(report)

        loaded = ci.load_previous()
        assert loaded is not None
        assert len(loaded.findings) == 1
        lf = loaded.findings[0]
        assert lf.check_id == "SEC-005"
        assert lf.severity == Severity.CRITICAL
        assert lf.category == Category.SECURITY
        assert lf.message == "Debug mode enabled"
        assert str(lf.file) == "settings.py"
        assert lf.line == 99

    def test_save_records_score_metadata(self, tmp_path: Path):
        """Saved scan should record total_lines, total_files, and score in the DB."""
        report = _report(score=77, findings=[], total_lines=5000, total_files=42)
        ci = CIScanDiff(tmp_path)

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            ci.save_scan(report)

        db_path = tmp_path / ".devnog" / "history.db"
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT overall_score, total_lines, total_files FROM scan_history"
        ).fetchone()
        conn.close()

        assert row[0] == 77
        assert row[1] == 5000
        assert row[2] == 42

    def test_save_handles_git_failure_gracefully(self, tmp_path: Path):
        """save_scan() should still succeed even if git commands fail."""
        report = _report(score=80, findings=[])
        ci = CIScanDiff(tmp_path)

        with patch("subprocess.run", side_effect=OSError("git not found")):
            ci.save_scan(report)

        loaded = ci.load_previous()
        assert loaded is not None
        assert loaded.overall_score == 80
