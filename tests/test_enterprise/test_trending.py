"""Tests for HistoryTracker: storing scans, querying trends, regression alerts."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devnog.core.models import Category, CategoryScore, Finding, ScanReport, Severity
from devnog.enterprise.trending import HistoryEntry, HistoryTracker, RegressionAlert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    check_id: str = "SEC-001",
    category: Category = Category.SECURITY,
    severity: Severity = Severity.WARNING,
    message: str = "issue",
    file: str = "app.py",
    line: int = 1,
) -> Finding:
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
    total_lines: int = 500,
    total_files: int = 5,
    category_scores: dict[str, CategoryScore] | None = None,
) -> ScanReport:
    return ScanReport(
        overall_score=score,
        findings=findings or [],
        total_lines=total_lines,
        total_files=total_files,
        category_scores=category_scores or {},
    )


def _mock_subprocess_run(*args, **kwargs):
    """Mock subprocess.run that returns an object with a .stdout attribute."""
    result = MagicMock()
    result.stdout = ""
    return result


def _insert_history_row(
    db_path: Path,
    overall_score: int,
    scanned_at: str | None = None,
    security_score: int = 0,
    error_handling_score: int = 0,
    code_quality_score: int = 0,
    dependencies_score: int = 0,
    total_issues: int = 0,
    critical_issues: int = 0,
    warning_issues: int = 0,
    info_issues: int = 0,
    total_lines: int = 0,
    total_files: int = 0,
    git_commit: str = "",
    git_branch: str = "",
) -> None:
    """Insert a row directly into scan_history for test setup."""
    if scanned_at is None:
        scanned_at = datetime.now().isoformat()
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """INSERT INTO scan_history
           (scanned_at, overall_score, security_score, error_handling_score,
            code_quality_score, dependencies_score, total_issues,
            critical_issues, warning_issues, info_issues,
            total_lines, total_files, git_commit, git_branch, findings_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scanned_at, overall_score, security_score, error_handling_score,
            code_quality_score, dependencies_score, total_issues,
            critical_issues, warning_issues, info_issues,
            total_lines, total_files, git_commit, git_branch, "[]",
        ),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# HistoryTracker init
# ---------------------------------------------------------------------------

class TestHistoryTrackerInit:
    """Tests for HistoryTracker initialization."""

    def test_creates_devnog_dir(self, tmp_path: Path):
        """HistoryTracker should create the .devnog directory."""
        tracker = HistoryTracker(tmp_path)
        assert (tmp_path / ".devnog").is_dir()

    def test_creates_database(self, tmp_path: Path):
        """HistoryTracker should create history.db in .devnog."""
        tracker = HistoryTracker(tmp_path)
        assert tracker.db_path.exists()

    def test_table_exists_after_init(self, tmp_path: Path):
        """The scan_history table should exist after initialization."""
        tracker = HistoryTracker(tmp_path)
        conn = sqlite3.connect(str(tracker.db_path))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'"
        ).fetchall()
        conn.close()
        assert len(tables) == 1

    def test_repeated_init_is_idempotent(self, tmp_path: Path):
        """Creating multiple HistoryTrackers for the same path should not fail."""
        tracker1 = HistoryTracker(tmp_path)
        tracker2 = HistoryTracker(tmp_path)
        assert tracker2.db_path.exists()


# ---------------------------------------------------------------------------
# record()
# ---------------------------------------------------------------------------

class TestHistoryTrackerRecord:
    """Tests for HistoryTracker.record()."""

    def test_record_stores_scan(self, tmp_path: Path):
        """record() should insert a row into scan_history."""
        tracker = HistoryTracker(tmp_path)
        report = _report(score=85)

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            tracker.record(report)

        conn = sqlite3.connect(str(tracker.db_path))
        count = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        conn.close()
        assert count == 1

    def test_record_multiple_scans(self, tmp_path: Path):
        """record() should add rows incrementally."""
        tracker = HistoryTracker(tmp_path)

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            tracker.record(_report(score=70))
            tracker.record(_report(score=75))
            tracker.record(_report(score=80))

        conn = sqlite3.connect(str(tracker.db_path))
        count = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        conn.close()
        assert count == 3

    def test_record_preserves_score(self, tmp_path: Path):
        """Recorded score should be retrievable from the database."""
        tracker = HistoryTracker(tmp_path)
        report = _report(score=92)

        with patch("subprocess.run", side_effect=_mock_subprocess_run):
            tracker.record(report)

        conn = sqlite3.connect(str(tracker.db_path))
        row = conn.execute("SELECT overall_score FROM scan_history").fetchone()
        conn.close()
        assert row[0] == 92


# ---------------------------------------------------------------------------
# get_trend()
# ---------------------------------------------------------------------------

class TestHistoryTrackerGetTrend:
    """Tests for HistoryTracker.get_trend()."""

    def test_get_trend_empty_returns_empty_list(self, tmp_path: Path):
        """get_trend() on empty DB should return an empty list."""
        tracker = HistoryTracker(tmp_path)
        assert tracker.get_trend() == []

    def test_get_trend_returns_entries(self, tmp_path: Path):
        """get_trend() should return HistoryEntry objects."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now().isoformat()
        _insert_history_row(tracker.db_path, overall_score=80, scanned_at=now)

        entries = tracker.get_trend(days=90)
        assert len(entries) == 1
        assert isinstance(entries[0], HistoryEntry)
        assert entries[0].overall_score == 80

    def test_get_trend_ordered_by_date(self, tmp_path: Path):
        """Trend entries should be ordered chronologically (ascending)."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=70,
            scanned_at=(now - timedelta(days=5)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=80,
            scanned_at=(now - timedelta(days=2)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=90,
            scanned_at=now.isoformat(),
        )

        entries = tracker.get_trend(days=90)
        assert len(entries) == 3
        assert entries[0].overall_score == 70
        assert entries[1].overall_score == 80
        assert entries[2].overall_score == 90

    def test_get_trend_filters_by_days(self, tmp_path: Path):
        """get_trend(days=N) should only return entries within the last N days."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        # Old entry (100 days ago)
        _insert_history_row(
            tracker.db_path, overall_score=50,
            scanned_at=(now - timedelta(days=100)).isoformat(),
        )
        # Recent entry (2 days ago)
        _insert_history_row(
            tracker.db_path, overall_score=85,
            scanned_at=(now - timedelta(days=2)).isoformat(),
        )

        entries = tracker.get_trend(days=30)
        assert len(entries) == 1
        assert entries[0].overall_score == 85

    def test_get_trend_includes_all_fields(self, tmp_path: Path):
        """HistoryEntry should populate all score fields."""
        tracker = HistoryTracker(tmp_path)
        _insert_history_row(
            tracker.db_path,
            overall_score=75,
            security_score=80,
            error_handling_score=70,
            code_quality_score=65,
            dependencies_score=90,
            total_issues=12,
            critical_issues=2,
            warning_issues=5,
            info_issues=5,
            total_lines=3000,
            total_files=25,
            git_commit="abc123",
            git_branch="main",
        )

        entries = tracker.get_trend(days=90)
        assert len(entries) == 1
        e = entries[0]
        assert e.security_score == 80
        assert e.error_handling_score == 70
        assert e.code_quality_score == 65
        assert e.dependencies_score == 90
        assert e.total_issues == 12
        assert e.critical_issues == 2
        assert e.warning_issues == 5
        assert e.info_issues == 5
        assert e.total_lines == 3000
        assert e.total_files == 25
        assert e.git_commit == "abc123"
        assert e.git_branch == "main"


# ---------------------------------------------------------------------------
# get_category_trends()
# ---------------------------------------------------------------------------

class TestHistoryTrackerCategoryTrends:
    """Tests for HistoryTracker.get_category_trends()."""

    def test_category_trends_empty(self, tmp_path: Path):
        """Empty DB should return empty lists for all categories."""
        tracker = HistoryTracker(tmp_path)
        trends = tracker.get_category_trends()

        assert trends == {
            "security": [],
            "error_handling": [],
            "code_quality": [],
            "dependencies": [],
        }

    def test_category_trends_populated(self, tmp_path: Path):
        """Should return per-category score lists matching entry order."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=70,
            security_score=60, error_handling_score=70,
            code_quality_score=80, dependencies_score=90,
            scanned_at=(now - timedelta(days=2)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=75,
            security_score=65, error_handling_score=75,
            code_quality_score=85, dependencies_score=85,
            scanned_at=(now - timedelta(days=1)).isoformat(),
        )

        trends = tracker.get_category_trends(days=90)
        assert trends["security"] == [60, 65]
        assert trends["error_handling"] == [70, 75]
        assert trends["code_quality"] == [80, 85]
        assert trends["dependencies"] == [90, 85]

    def test_category_trends_respects_days_filter(self, tmp_path: Path):
        """Category trends should also filter by day window."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=50,
            security_score=40,
            scanned_at=(now - timedelta(days=200)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=80,
            security_score=75,
            scanned_at=now.isoformat(),
        )

        trends = tracker.get_category_trends(days=30)
        assert trends["security"] == [75]


# ---------------------------------------------------------------------------
# get_regression_alerts()
# ---------------------------------------------------------------------------

class TestHistoryTrackerRegressionAlerts:
    """Tests for HistoryTracker.get_regression_alerts()."""

    def test_no_alerts_on_steady_scores(self, tmp_path: Path):
        """Stable scores should produce no regression alerts."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=80,
            scanned_at=(now - timedelta(days=3)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=81,
            scanned_at=(now - timedelta(days=2)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=80,
            scanned_at=(now - timedelta(days=1)).isoformat(),
        )

        alerts = tracker.get_regression_alerts()
        assert alerts == []

    def test_alert_on_large_drop(self, tmp_path: Path):
        """A score drop > 5 should trigger a regression alert."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=85,
            scanned_at=(now - timedelta(days=2)).isoformat(),
            git_commit="aaa111",
        )
        _insert_history_row(
            tracker.db_path, overall_score=70,
            scanned_at=(now - timedelta(days=1)).isoformat(),
            git_commit="bbb222",
        )

        alerts = tracker.get_regression_alerts()
        assert len(alerts) == 1
        assert isinstance(alerts[0], RegressionAlert)
        assert alerts[0].from_score == 85
        assert alerts[0].to_score == 70
        assert alerts[0].delta == -15
        assert alerts[0].git_commit == "bbb222"

    def test_no_alert_on_exactly_minus_five(self, tmp_path: Path):
        """A drop of exactly 5 should NOT trigger an alert (must be > 5)."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=80,
            scanned_at=(now - timedelta(days=2)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=75,
            scanned_at=(now - timedelta(days=1)).isoformat(),
        )

        alerts = tracker.get_regression_alerts()
        assert alerts == []

    def test_multiple_regressions(self, tmp_path: Path):
        """Multiple large drops should each produce a separate alert."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        scores = [90, 80, 85, 70, 75]  # Drops: -10, +5, -15, +5
        for i, score in enumerate(scores):
            _insert_history_row(
                tracker.db_path, overall_score=score,
                scanned_at=(now - timedelta(days=len(scores) - i)).isoformat(),
            )

        alerts = tracker.get_regression_alerts()
        assert len(alerts) == 2
        assert alerts[0].delta == -10  # 90 -> 80
        assert alerts[1].delta == -15  # 85 -> 70

    def test_no_alert_on_improvement(self, tmp_path: Path):
        """Score improvements should never produce alerts."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=50,
            scanned_at=(now - timedelta(days=2)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=90,
            scanned_at=(now - timedelta(days=1)).isoformat(),
        )

        alerts = tracker.get_regression_alerts()
        assert alerts == []

    def test_alert_only_within_30_days(self, tmp_path: Path):
        """Regression alerts should only consider the last 30 days of data."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        # Old regression (40 days ago)
        _insert_history_row(
            tracker.db_path, overall_score=90,
            scanned_at=(now - timedelta(days=40)).isoformat(),
        )
        _insert_history_row(
            tracker.db_path, overall_score=50,
            scanned_at=(now - timedelta(days=39)).isoformat(),
        )
        # Recent stability
        _insert_history_row(
            tracker.db_path, overall_score=80,
            scanned_at=(now - timedelta(days=1)).isoformat(),
        )

        alerts = tracker.get_regression_alerts()
        # The old drop (90->50) is outside 30-day window, should not appear
        assert alerts == []

    def test_alert_empty_history(self, tmp_path: Path):
        """No data should produce no alerts."""
        tracker = HistoryTracker(tmp_path)
        alerts = tracker.get_regression_alerts()
        assert alerts == []

    def test_alert_single_entry_no_alert(self, tmp_path: Path):
        """A single history entry cannot produce a regression alert."""
        tracker = HistoryTracker(tmp_path)
        now = datetime.now()

        _insert_history_row(
            tracker.db_path, overall_score=80,
            scanned_at=now.isoformat(),
        )

        alerts = tracker.get_regression_alerts()
        assert alerts == []
