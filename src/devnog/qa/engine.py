"""QA Gate engine — orchestrates all QA checks and computes a verdict."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Finding, QAVerdict, Severity
from devnog.qa.checks import ALL_QA_CHECKS
from devnog.qa.checks.base import QACheck


class QAGate:
    """Production-readiness gate that runs all QA checks on a project.

    Usage::

        gate = QAGate(project_path=Path("/my/project"))
        verdict = gate.evaluate()
        print(verdict.verdict, verdict.score)

    Verdict logic
    -------------
    * **PASS** — all *required* checks pass and the score is >= 80.
    * **CONDITIONAL PASS** — no required failures, warnings exist,
      score is between 60 and 79 inclusive.
    * **FAIL** — any required check fails, or the score is < 60.
    """

    def __init__(
        self,
        project_path: Path | None = None,
        checks: list[type[QACheck]] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> None:
        self.project_path = (project_path or Path.cwd()).resolve()
        self._check_classes = checks or list(ALL_QA_CHECKS)
        self._exclude_patterns = exclude_patterns or [
            "__pycache__",
            ".git",
            ".venv",
            "venv",
            "node_modules",
            ".tox",
            ".mypy_cache",
            "dist",
            "build",
            ".eggs",
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, target_path: Path | None = None) -> QAVerdict:
        """Run every registered QA check and return a :class:`QAVerdict`."""
        scan_path = target_path or self.project_path

        source_files = self._collect_source_files(scan_path)
        checks = [cls() for cls in self._check_classes]

        all_findings: list[Finding] = []
        for check in checks:
            try:
                check_findings = check.run(scan_path, source_files)
                # Normalise file paths to be relative to the project root.
                for f in check_findings:
                    if f.file:
                        try:
                            f.file = f.file.relative_to(self.project_path)
                        except ValueError:
                            pass  # path is not relative to project root; keep as-is
                all_findings.extend(check_findings)
            except Exception:
                # Never let a broken check abort the entire gate.
                continue

        return self._compute_verdict(all_findings, checks)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _collect_source_files(
        self, path: Path
    ) -> list[tuple[Path, str, ast.Module]]:
        """Collect and parse all Python files under *path*."""
        result: list[tuple[Path, str, ast.Module]] = []

        if path.is_file() and path.suffix == ".py":
            return self._try_parse(path, result)

        for py_file in sorted(path.rglob("*.py")):
            rel = str(py_file.relative_to(path))
            if any(excl in rel for excl in self._exclude_patterns):
                continue
            self._try_parse(py_file, result)

        return result

    @staticmethod
    def _try_parse(
        py_file: Path,
        accumulator: list[tuple[Path, str, ast.Module]],
    ) -> list[tuple[Path, str, ast.Module]]:
        try:
            source = py_file.read_text(errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
            accumulator.append((py_file, source, tree))
        except (SyntaxError, UnicodeDecodeError):
            pass  # skip unparseable files
        return accumulator

    # ------------------------------------------------------------------

    def _compute_verdict(
        self,
        findings: list[Finding],
        checks: list[QACheck],
    ) -> QAVerdict:
        """Derive the score and verdict string from findings."""
        passed: list[Finding] = []
        warnings: list[Finding] = []
        failures: list[Finding] = []

        required_check_ids = {c.check_id for c in checks if c.required}

        for f in findings:
            if f.severity == Severity.CRITICAL:
                failures.append(f)
            elif f.severity == Severity.WARNING:
                warnings.append(f)
            else:
                passed.append(f)

        # --- score --------------------------------------------------------
        score = self._calculate_score(findings, checks)

        # --- required-check failures -------------------------------------
        has_required_failure = any(
            f.check_id in required_check_ids for f in failures
        )

        # --- verdict string -----------------------------------------------
        if has_required_failure or score < 60:
            verdict_str = "FAIL"
        elif warnings and score < 80:
            verdict_str = "CONDITIONAL PASS"
        else:
            verdict_str = "PASS"

        return QAVerdict(
            verdict=verdict_str,
            score=score,
            passed_checks=passed,
            warnings=warnings,
            failures=failures,
        )

    @staticmethod
    def _calculate_score(
        findings: list[Finding],
        checks: list[QACheck],
    ) -> int:
        """Compute a 0-100 score.

        Scoring methodology:
        * Start at 100.
        * Each CRITICAL finding deducts 15 points.
        * Each WARNING finding deducts 5 points.
        * Each INFO finding deducts 1 point.
        * Floor at 0.
        """
        score = 100
        for f in findings:
            if f.severity == Severity.CRITICAL:
                score -= 15
            elif f.severity == Severity.WARNING:
                score -= 5
            else:
                score -= 1
        return max(0, min(100, score))
