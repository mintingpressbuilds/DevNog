"""Historical score tracking (Enterprise)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from devnog.core.config import get_devnog_dir


@dataclass
class HistoryEntry:
    """A single scan history entry."""

    scanned_at: datetime
    overall_score: int
    security_score: int = 0
    error_handling_score: int = 0
    code_quality_score: int = 0
    dependencies_score: int = 0
    total_issues: int = 0
    critical_issues: int = 0
    warning_issues: int = 0
    info_issues: int = 0
    total_lines: int = 0
    total_files: int = 0
    git_commit: str = ""
    git_branch: str = ""


@dataclass
class RegressionAlert:
    """Alert for significant score drop."""

    from_score: int
    to_score: int
    delta: int
    date: datetime
    git_commit: str = ""


class HistoryTracker:
    """Stores and queries scan history over time."""

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.devnog_dir = get_devnog_dir(project_path)
        self.db_path = self.devnog_dir / "history.db"
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create history table if it doesn't exist."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TIMESTAMP NOT NULL,
                overall_score INTEGER NOT NULL,
                security_score INTEGER DEFAULT 0,
                error_handling_score INTEGER DEFAULT 0,
                code_quality_score INTEGER DEFAULT 0,
                dependencies_score INTEGER DEFAULT 0,
                total_issues INTEGER DEFAULT 0,
                critical_issues INTEGER DEFAULT 0,
                warning_issues INTEGER DEFAULT 0,
                info_issues INTEGER DEFAULT 0,
                total_lines INTEGER DEFAULT 0,
                total_files INTEGER DEFAULT 0,
                git_commit VARCHAR(40) DEFAULT '',
                git_branch VARCHAR(128) DEFAULT '',
                findings_json TEXT DEFAULT '[]'
            )
        """)
        conn.commit()
        conn.close()

    def record(self, report) -> None:
        """Append current scan to history."""
        from devnog.enterprise.ci_gate import CIScanDiff
        ci = CIScanDiff(self.project_path)
        ci.save_scan(report)

    def get_trend(self, days: int = 90) -> list[HistoryEntry]:
        """Get score history for last N days."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                """SELECT scanned_at, overall_score, security_score,
                          error_handling_score, code_quality_score, dependencies_score,
                          total_issues, critical_issues, warning_issues, info_issues,
                          total_lines, total_files, git_commit, git_branch
                   FROM scan_history
                   WHERE scanned_at >= datetime('now', ?)
                   ORDER BY scanned_at ASC""",
                (f"-{days} days",),
            ).fetchall()

            return [
                HistoryEntry(
                    scanned_at=datetime.fromisoformat(r[0]),
                    overall_score=r[1],
                    security_score=r[2] or 0,
                    error_handling_score=r[3] or 0,
                    code_quality_score=r[4] or 0,
                    dependencies_score=r[5] or 0,
                    total_issues=r[6] or 0,
                    critical_issues=r[7] or 0,
                    warning_issues=r[8] or 0,
                    info_issues=r[9] or 0,
                    total_lines=r[10] or 0,
                    total_files=r[11] or 0,
                    git_commit=r[12] or "",
                    git_branch=r[13] or "",
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_category_trends(self, days: int = 90) -> dict[str, list[float]]:
        """Per-category score progression."""
        entries = self.get_trend(days)
        return {
            "security": [e.security_score for e in entries],
            "error_handling": [e.error_handling_score for e in entries],
            "code_quality": [e.code_quality_score for e in entries],
            "dependencies": [e.dependencies_score for e in entries],
        }

    def get_regression_alerts(self) -> list[RegressionAlert]:
        """Detect significant score drops (>5 points in one scan)."""
        entries = self.get_trend(days=30)
        alerts = []

        for i in range(1, len(entries)):
            delta = entries[i].overall_score - entries[i - 1].overall_score
            if delta < -5:
                alerts.append(RegressionAlert(
                    from_score=entries[i - 1].overall_score,
                    to_score=entries[i].overall_score,
                    delta=delta,
                    date=entries[i].scanned_at,
                    git_commit=entries[i].git_commit,
                ))

        return alerts
