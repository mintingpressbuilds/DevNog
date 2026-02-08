"""CI/CD scan diff and regression blocking."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from devnog.core.config import get_devnog_dir
from devnog.core.models import Finding, ScanReport, Severity


@dataclass
class ScanDiff:
    """Diff between two scans."""

    previous_score: int
    current_score: int
    score_delta: int
    new_issues: list[Finding] = field(default_factory=list)
    resolved_issues: list[Finding] = field(default_factory=list)
    unchanged_issues: list[Finding] = field(default_factory=list)
    verdict: str = "pass"  # "pass", "warning", "blocked"


class CIScanDiff:
    """Compares scans and produces diffs for CI/CD pipelines."""

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.devnog_dir = get_devnog_dir(project_path)

    def diff(self, current: ScanReport, previous: ScanReport) -> ScanDiff:
        """Produce a diff between two scans."""
        prev_ids = {f.check_id + ":" + str(f.file) + ":" + str(f.line) for f in previous.findings}
        curr_ids = {f.check_id + ":" + str(f.file) + ":" + str(f.line) for f in current.findings}

        new_issues = [
            f for f in current.findings
            if f.check_id + ":" + str(f.file) + ":" + str(f.line) not in prev_ids
        ]
        resolved_issues = [
            f for f in previous.findings
            if f.check_id + ":" + str(f.file) + ":" + str(f.line) not in curr_ids
        ]
        unchanged_issues = [
            f for f in current.findings
            if f.check_id + ":" + str(f.file) + ":" + str(f.line) in prev_ids
        ]

        score_delta = current.overall_score - previous.overall_score

        # Determine verdict
        has_new_critical = any(f.severity == Severity.CRITICAL for f in new_issues)
        has_new_warning = any(f.severity == Severity.WARNING for f in new_issues)

        if has_new_critical:
            verdict = "blocked"
        elif has_new_warning or score_delta < -5:
            verdict = "warning"
        else:
            verdict = "pass"

        return ScanDiff(
            previous_score=previous.overall_score,
            current_score=current.overall_score,
            score_delta=score_delta,
            new_issues=new_issues,
            resolved_issues=resolved_issues,
            unchanged_issues=unchanged_issues,
            verdict=verdict,
        )

    def format_ci_output(self, diff: ScanDiff) -> str:
        """Format diff for CI log output (plain text)."""
        lines = [
            "DevNog CI Scan Diff",
            f"Score: {diff.previous_score} -> {diff.current_score} ({diff.score_delta:+d})",
            "",
        ]

        if diff.new_issues:
            lines.append("New issues introduced:")
            for f in diff.new_issues:
                icon = "CRITICAL" if f.severity == Severity.CRITICAL else "WARNING" if f.severity == Severity.WARNING else "INFO"
                lines.append(f"  [{icon}] {f.check_id}  {f.message}  {f.file}:{f.line}")
            lines.append("")

        if diff.resolved_issues:
            lines.append("Issues resolved:")
            for f in diff.resolved_issues:
                lines.append(f"  [FIXED] {f.check_id}  {f.message}")
            lines.append("")

        verdict_msg = {
            "pass": "PASSED",
            "warning": "WARNING -- new issues detected",
            "blocked": "BLOCKED -- new critical issues introduced",
        }
        lines.append(f"Verdict: {verdict_msg.get(diff.verdict, diff.verdict)}")

        return "\n".join(lines)

    def generate_pr_comment(self, diff: ScanDiff) -> str:
        """Generate markdown for a GitHub PR comment."""
        emoji = {"pass": "white_check_mark", "warning": "warning", "blocked": "x"}
        icon = emoji.get(diff.verdict, "question")

        lines = [
            f"## DevNog Scan Diff :{icon}:",
            "",
            f"**Score:** {diff.previous_score} -> {diff.current_score} ({diff.score_delta:+d})",
            "",
        ]

        if diff.new_issues:
            lines.append("### New Issues")
            for f in diff.new_issues:
                sev = "red_circle" if f.severity == Severity.CRITICAL else "yellow_circle"
                lines.append(f"- :{sev}: **{f.check_id}** {f.message} (`{f.file}:{f.line}`)")
            lines.append("")

        if diff.resolved_issues:
            lines.append("### Resolved")
            for f in diff.resolved_issues:
                lines.append(f"- :white_check_mark: **{f.check_id}** {f.message}")
            lines.append("")

        return "\n".join(lines)

    def save_scan(self, report: ScanReport) -> None:
        """Save current scan to history for future diffs."""
        db_path = self.devnog_dir / "history.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TIMESTAMP NOT NULL,
                overall_score INTEGER NOT NULL,
                security_score INTEGER,
                error_handling_score INTEGER,
                code_quality_score INTEGER,
                dependencies_score INTEGER,
                total_issues INTEGER,
                critical_issues INTEGER,
                warning_issues INTEGER,
                info_issues INTEGER,
                total_lines INTEGER,
                total_files INTEGER,
                git_commit VARCHAR(40),
                git_branch VARCHAR(128),
                findings_json TEXT
            )
        """)

        # Get git info
        import subprocess
        git_commit = ""
        git_branch = ""
        try:
            git_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, cwd=str(self.project_path),
            ).stdout.strip()
            git_branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, cwd=str(self.project_path),
            ).stdout.strip()
        except Exception:
            pass  # git may not be available; proceed without VCS metadata

        findings_json = json.dumps([
            {
                "check_id": f.check_id,
                "category": f.category.value,
                "severity": f.severity.value,
                "message": f.message,
                "file": str(f.file),
                "line": f.line,
            }
            for f in report.findings
        ])

        conn.execute(
            """INSERT INTO scan_history
            (scanned_at, overall_score, security_score, error_handling_score,
             code_quality_score, dependencies_score, total_issues,
             critical_issues, warning_issues, info_issues,
             total_lines, total_files, git_commit, git_branch, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                report.overall_score,
                report.category_scores.get("security", type("", (), {"score": 0})).score,
                report.category_scores.get("error_handling", type("", (), {"score": 0})).score,
                report.category_scores.get("code_quality", type("", (), {"score": 0})).score,
                report.category_scores.get("dependencies", type("", (), {"score": 0})).score,
                len(report.findings),
                report.critical_count,
                report.warning_count,
                report.info_count,
                report.total_lines,
                report.total_files,
                git_commit,
                git_branch,
                findings_json,
            ),
        )
        conn.commit()
        conn.close()

    def load_previous(self) -> ScanReport | None:
        """Load the most recent scan from history."""
        db_path = self.devnog_dir / "history.db"
        if not db_path.exists():
            return None

        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT overall_score, findings_json FROM scan_history ORDER BY id DESC LIMIT 1"
            ).fetchone()

            if not row:
                return None

            findings_data = json.loads(row[1]) if row[1] else []
            from devnog.core.models import Category
            findings = []
            for fd in findings_data:
                findings.append(Finding(
                    check_id=fd["check_id"],
                    category=Category(fd["category"]),
                    severity=Severity(fd["severity"]),
                    message=fd["message"],
                    file=Path(fd["file"]) if fd.get("file") else None,
                    line=fd.get("line"),
                ))

            return ScanReport(
                overall_score=row[0],
                findings=findings,
            )
        finally:
            conn.close()
