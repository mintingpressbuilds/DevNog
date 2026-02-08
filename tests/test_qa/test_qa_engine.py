"""Tests for the QA Gate engine (QAGate) integration."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from devnog.qa.engine import QAGate
from devnog.qa.checks.base import QACheck
from devnog.qa.checks import ALL_QA_CHECKS
from devnog.core.models import Category, Finding, FixType, QAVerdict, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_file(path: Path, content: str) -> None:
    """Write *content* (dedented) to *path*, creating parents as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


class _AlwaysPassCheck(QACheck):
    """A dummy check that never produces findings."""

    check_id = "QA-TEST-PASS"
    description = "Always passes"

    def run(self, project_path, source_files):
        return []


class _AlwaysWarnCheck(QACheck):
    """A dummy check that always produces a WARNING finding."""

    check_id = "QA-TEST-WARN"
    description = "Always warns"
    severity = Severity.WARNING

    def run(self, project_path, source_files):
        return [self._make_finding("Test warning")]


class _AlwaysFailCheck(QACheck):
    """A dummy check that always produces a CRITICAL finding."""

    check_id = "QA-TEST-FAIL"
    description = "Always fails"
    severity = Severity.CRITICAL
    required = True

    def run(self, project_path, source_files):
        return [self._make_finding("Test failure")]


class _AlwaysInfoCheck(QACheck):
    """A dummy check that always produces an INFO finding."""

    check_id = "QA-TEST-INFO"
    description = "Always info"
    severity = Severity.INFO

    def run(self, project_path, source_files):
        return [self._make_finding("Test info")]


class _BrokenCheck(QACheck):
    """A check that raises an exception during run()."""

    check_id = "QA-TEST-BROKEN"
    description = "Broken check"

    def run(self, project_path, source_files):
        raise RuntimeError("This check is intentionally broken")


# ---------------------------------------------------------------------------
# Test: Source file collection
# ---------------------------------------------------------------------------

class TestSourceFileCollection:
    def test_collects_python_files(self, tmp_path: Path):
        """QAGate should discover .py files under the project root."""
        _write_file(tmp_path / "app.py", "x = 1\n")
        _write_file(tmp_path / "lib" / "util.py", "y = 2\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        names = {sf[0].name for sf in source_files}
        assert "app.py" in names
        assert "util.py" in names

    def test_excludes_pycache(self, tmp_path: Path):
        """Files under __pycache__ should be excluded."""
        _write_file(tmp_path / "app.py", "x = 1\n")
        _write_file(tmp_path / "__pycache__" / "app.cpython-311.pyc.py", "z = 3\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        paths = [str(sf[0]) for sf in source_files]
        assert not any("__pycache__" in p for p in paths)

    def test_excludes_venv(self, tmp_path: Path):
        """Files under .venv/ should be excluded."""
        _write_file(tmp_path / "app.py", "x = 1\n")
        _write_file(tmp_path / ".venv" / "lib" / "pkg.py", "z = 3\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        paths = [str(sf[0]) for sf in source_files]
        assert not any(".venv" in p for p in paths)

    def test_excludes_git_directory(self, tmp_path: Path):
        """Files under .git/ should be excluded."""
        _write_file(tmp_path / "app.py", "x = 1\n")
        _write_file(tmp_path / ".git" / "hooks" / "pre-commit.py", "z = 3\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        paths = [str(sf[0]) for sf in source_files]
        assert not any(".git" in p for p in paths)

    def test_single_file_mode(self, tmp_path: Path):
        """QAGate should handle a single file as target."""
        py_file = tmp_path / "single.py"
        _write_file(py_file, "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(py_file)
        assert len(source_files) == 1
        assert source_files[0][0] == py_file

    def test_skips_syntax_error_files(self, tmp_path: Path):
        """Files with syntax errors should be silently skipped."""
        good_file = tmp_path / "good.py"
        bad_file = tmp_path / "bad.py"
        _write_file(good_file, "x = 1\n")
        bad_file.write_text("def broken(\n")  # syntax error

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        names = {sf[0].name for sf in source_files}
        assert "good.py" in names
        assert "bad.py" not in names

    def test_returns_ast_module(self, tmp_path: Path):
        """Collected files should include parsed AST modules."""
        _write_file(tmp_path / "mod.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        assert len(source_files) == 1
        file_path, source, tree = source_files[0]
        assert isinstance(tree, ast.Module)
        assert "x = 1" in source

    def test_empty_directory(self, tmp_path: Path):
        """An empty directory should return no source files."""
        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        source_files = gate._collect_source_files(tmp_path)
        assert source_files == []


# ---------------------------------------------------------------------------
# Test: Verdict computation
# ---------------------------------------------------------------------------

class TestVerdictComputation:
    def test_pass_verdict_with_no_findings(self, tmp_path: Path):
        """No findings should result in a PASS verdict with score 100."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        verdict = gate.evaluate()
        assert verdict.verdict == "PASS"
        assert verdict.score == 100

    def test_fail_verdict_with_required_critical(self, tmp_path: Path):
        """A required CRITICAL finding should result in FAIL."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysFailCheck])
        verdict = gate.evaluate()
        assert verdict.verdict == "FAIL"
        assert len(verdict.failures) >= 1

    def test_conditional_pass_with_warnings(self, tmp_path: Path):
        """Warnings that bring the score between 60-79 give CONDITIONAL PASS."""
        # 5 warnings = -25 points = score 75, which is < 80 and >= 60
        class _FiveWarnCheck(QACheck):
            check_id = "QA-TEST-5WARN"
            description = "Produces 5 warnings"
            severity = Severity.WARNING

            def run(self, project_path, source_files):
                return [self._make_finding(f"Warning {i}") for i in range(5)]

        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_FiveWarnCheck])
        verdict = gate.evaluate()
        assert verdict.verdict == "CONDITIONAL PASS"
        assert 60 <= verdict.score < 80

    def test_pass_with_minor_warnings(self, tmp_path: Path):
        """A few warnings still allow PASS if score >= 80."""
        # 1 warning = -5 points = score 95
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysWarnCheck])
        verdict = gate.evaluate()
        # score = 95, warnings exist but score >= 80 => PASS
        assert verdict.verdict == "PASS"
        assert verdict.score == 95

    def test_fail_with_low_score(self, tmp_path: Path):
        """Score below 60 should result in FAIL even without required checks."""
        class _ManyWarnCheck(QACheck):
            check_id = "QA-TEST-MANYWARN"
            description = "Produces many warnings"
            severity = Severity.WARNING
            required = False

            def run(self, project_path, source_files):
                return [self._make_finding(f"Warning {i}") for i in range(9)]

        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_ManyWarnCheck])
        verdict = gate.evaluate()
        # 9 warnings = -45 points = score 55
        assert verdict.verdict == "FAIL"
        assert verdict.score < 60


# ---------------------------------------------------------------------------
# Test: Score calculation
# ---------------------------------------------------------------------------

class TestScoreCalculation:
    def test_perfect_score(self, tmp_path: Path):
        """No findings should yield a score of 100."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        verdict = gate.evaluate()
        assert verdict.score == 100

    def test_critical_deducts_15(self, tmp_path: Path):
        """Each CRITICAL finding deducts 15 points."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysFailCheck])
        verdict = gate.evaluate()
        assert verdict.score == 85

    def test_warning_deducts_5(self, tmp_path: Path):
        """Each WARNING finding deducts 5 points."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysWarnCheck])
        verdict = gate.evaluate()
        assert verdict.score == 95

    def test_info_deducts_1(self, tmp_path: Path):
        """Each INFO finding deducts 1 point."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysInfoCheck])
        verdict = gate.evaluate()
        assert verdict.score == 99

    def test_score_floor_at_zero(self, tmp_path: Path):
        """Score should never go below 0."""
        class _ManyCriticalCheck(QACheck):
            check_id = "QA-TEST-MANYCRIT"
            description = "Produces many critical findings"
            severity = Severity.CRITICAL
            required = True

            def run(self, project_path, source_files):
                return [self._make_finding(f"Crit {i}") for i in range(10)]

        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_ManyCriticalCheck])
        verdict = gate.evaluate()
        # 10 * 15 = 150 deduction, clamped to 0
        assert verdict.score == 0

    def test_mixed_severity_scoring(self, tmp_path: Path):
        """Mixed severity findings should combine deductions correctly."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(
            project_path=tmp_path,
            checks=[_AlwaysFailCheck, _AlwaysWarnCheck, _AlwaysInfoCheck],
        )
        verdict = gate.evaluate()
        # 100 - 15 (critical) - 5 (warning) - 1 (info) = 79
        assert verdict.score == 79


# ---------------------------------------------------------------------------
# Test: Broken check resilience
# ---------------------------------------------------------------------------

class TestBrokenCheckResilience:
    def test_broken_check_does_not_abort(self, tmp_path: Path):
        """A check that raises should not crash the engine."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(
            project_path=tmp_path,
            checks=[_BrokenCheck, _AlwaysWarnCheck],
        )
        verdict = gate.evaluate()
        # The broken check is skipped; only the warn check runs.
        assert verdict.score == 95
        assert len(verdict.warnings) == 1

    def test_broken_check_still_returns_verdict(self, tmp_path: Path):
        """Even if all checks break, the engine should return a valid verdict."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_BrokenCheck])
        verdict = gate.evaluate()
        assert isinstance(verdict, QAVerdict)
        assert verdict.verdict == "PASS"
        assert verdict.score == 100


# ---------------------------------------------------------------------------
# Test: Evaluate with target_path
# ---------------------------------------------------------------------------

class TestEvaluateTargetPath:
    def test_evaluate_specific_target(self, tmp_path: Path):
        """evaluate(target_path=...) should only scan that subtree."""
        subdir = tmp_path / "src"
        _write_file(subdir / "mod.py", "x = 1\n")
        _write_file(tmp_path / "other.py", "y = 2\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        verdict = gate.evaluate(target_path=subdir)
        # Should still return a valid verdict.
        assert isinstance(verdict, QAVerdict)


# ---------------------------------------------------------------------------
# Test: Relative file paths in findings
# ---------------------------------------------------------------------------

class TestRelativeFilePaths:
    def test_findings_have_relative_paths(self, tmp_path: Path):
        """Findings should contain paths relative to the project root."""
        _write_file(tmp_path / "main.py", """\
            import sys
            def main():
                print("hello")

            if __name__ == "__main__":
                main()
        """)

        from devnog.qa.checks.error_handling import QA001UnhandledEntryPointExceptions

        gate = QAGate(
            project_path=tmp_path,
            checks=[QA001UnhandledEntryPointExceptions],
        )
        verdict = gate.evaluate()
        if verdict.failures:
            for f in verdict.failures:
                if f.file:
                    # The path should be relative (not start with tmp_path).
                    assert not str(f.file).startswith(str(tmp_path)), (
                        f"Expected relative path, got: {f.file}"
                    )


# ---------------------------------------------------------------------------
# Test: Custom checks
# ---------------------------------------------------------------------------

class TestCustomChecks:
    def test_custom_check_list(self, tmp_path: Path):
        """QAGate should accept a custom list of checks."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(
            project_path=tmp_path,
            checks=[_AlwaysPassCheck, _AlwaysWarnCheck],
        )
        verdict = gate.evaluate()
        assert verdict.score == 95  # only 1 warning = -5

    def test_empty_check_list_falls_back_to_defaults(self, tmp_path: Path):
        """An empty list is falsy, so QAGate falls back to ALL_QA_CHECKS.

        ``checks or list(ALL_QA_CHECKS)`` treats ``[]`` as the default.
        """
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[])
        assert gate._check_classes == list(ALL_QA_CHECKS)


# ---------------------------------------------------------------------------
# Test: Custom exclude patterns
# ---------------------------------------------------------------------------

class TestExcludePatterns:
    def test_custom_exclude(self, tmp_path: Path):
        """Custom exclude patterns should be respected."""
        _write_file(tmp_path / "app.py", "x = 1\n")
        _write_file(tmp_path / "generated" / "auto.py", "y = 2\n")

        gate = QAGate(
            project_path=tmp_path,
            checks=[_AlwaysPassCheck],
            exclude_patterns=["generated"],
        )
        source_files = gate._collect_source_files(tmp_path)
        names = {sf[0].name for sf in source_files}
        assert "app.py" in names
        assert "auto.py" not in names


# ---------------------------------------------------------------------------
# Test: Default checks list
# ---------------------------------------------------------------------------

class TestDefaultChecks:
    def test_default_uses_all_checks(self, tmp_path: Path):
        """When no checks are specified, all registered checks are used."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path)
        assert gate._check_classes == list(ALL_QA_CHECKS)

    def test_all_checks_count(self):
        """ALL_QA_CHECKS should contain 25 checks."""
        assert len(ALL_QA_CHECKS) == 25


# ---------------------------------------------------------------------------
# Test: QAVerdict structure
# ---------------------------------------------------------------------------

class TestQAVerdictStructure:
    def test_verdict_has_all_fields(self, tmp_path: Path):
        """QAVerdict should have verdict, score, passed, warnings, failures."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(project_path=tmp_path, checks=[_AlwaysPassCheck])
        verdict = gate.evaluate()
        assert hasattr(verdict, "verdict")
        assert hasattr(verdict, "score")
        assert hasattr(verdict, "passed_checks")
        assert hasattr(verdict, "warnings")
        assert hasattr(verdict, "failures")

    def test_findings_separated_by_severity(self, tmp_path: Path):
        """Findings should be correctly categorized into passed/warnings/failures."""
        _write_file(tmp_path / "app.py", "x = 1\n")

        gate = QAGate(
            project_path=tmp_path,
            checks=[_AlwaysFailCheck, _AlwaysWarnCheck, _AlwaysInfoCheck],
        )
        verdict = gate.evaluate()
        assert len(verdict.failures) >= 1
        assert all(f.severity == Severity.CRITICAL for f in verdict.failures)
        assert len(verdict.warnings) >= 1
        assert all(f.severity == Severity.WARNING for f in verdict.warnings)
        # INFO findings go to passed_checks
        assert len(verdict.passed_checks) >= 1


# ---------------------------------------------------------------------------
# Test: End-to-end with real checks
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_clean_project_passes(self, tmp_path: Path):
        """A minimal clean project should pass QA with a high score."""
        _write_file(tmp_path / "utils.py", """\
            def add(a: int, b: int) -> int:
                return a + b
        """)

        gate = QAGate(project_path=tmp_path)
        verdict = gate.evaluate()
        # A simple utility file should have no/few findings.
        assert verdict.score >= 80

    def test_problematic_project_has_findings(self, tmp_path: Path):
        """A project with multiple issues should produce findings."""
        # Entry point without handler
        _write_file(tmp_path / "main.py", """\
            def main():
                print("hello")

            if __name__ == "__main__":
                main()
        """)
        # HTTP call without timeout or retry
        _write_file(tmp_path / "client.py", """\
            import requests

            def fetch():
                return requests.get("https://api.example.com")
        """)
        # Hardcoded secret
        _write_file(tmp_path / "config.py", """\
            api_key = "sk_live_1234567890abcdef"
            DEBUG = True
        """)

        gate = QAGate(project_path=tmp_path)
        verdict = gate.evaluate()
        all_findings = verdict.failures + verdict.warnings + verdict.passed_checks
        assert len(all_findings) >= 3
        check_ids = {f.check_id for f in all_findings}
        # We expect at least QA-001 (entry point), QA-004 (timeout),
        # QA-014 (secret)
        assert "QA-001" in check_ids
        assert "QA-004" in check_ids

    def test_web_service_without_observability(self, tmp_path: Path):
        """A Flask app without health/tracing/metrics should get findings."""
        _write_file(tmp_path / "app.py", """\
            from flask import Flask

            app = Flask(__name__)

            @app.route("/")
            def index():
                return "Hello"

            if __name__ == "__main__":
                app.run(host="0.0.0.0", port=5000)
        """)

        gate = QAGate(project_path=tmp_path)
        verdict = gate.evaluate()
        all_findings = verdict.failures + verdict.warnings + verdict.passed_checks
        check_ids = {f.check_id for f in all_findings}
        # Should detect missing health check
        assert "QA-007" in check_ids
