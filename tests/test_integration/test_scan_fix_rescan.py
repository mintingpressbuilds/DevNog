"""Integration test: scan -> fix -> rescan -> verify score improved."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.scanner.engine import Scanner
from devnog.scanner.scoring import compute_scores
from devnog.fix.rule_fixer import RuleBasedFixer
from devnog.fix.applier import FixApplier
from devnog.fix.undo import UndoManager
from devnog.core.config import DevNogConfig, ScanConfig
from devnog.core.models import Finding, Category, Severity, FixType, ScanReport


@pytest.fixture
def buggy_project(tmp_path: Path) -> Path:
    """Create a project with multiple fixable issues."""
    # Create .devnog dir for backup support
    (tmp_path / ".devnog").mkdir()

    # File with SEC-001 (hardcoded secret), SEC-006 (DEBUG=True), ERR-001 (bare except)
    app_code = '''\
import os

password = "super-secret-password-123"
DEBUG = True

def get_data():
    try:
        return do_risky_thing()
    except:
        pass
'''
    (tmp_path / "app.py").write_text(app_code)

    # File with SEC-009 (weak hash) and SEC-012 (subprocess shell=True)
    sec_code = '''\
import hashlib
import subprocess

def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)
'''
    (tmp_path / "security.py").write_text(sec_code)

    # File with ERR-007 (HTTP no timeout)
    api_code = '''\
import requests

def fetch():
    return requests.get("https://api.example.com/data")
'''
    (tmp_path / "api.py").write_text(api_code)

    return tmp_path


class TestScanFixRescan:
    def test_full_scan_fix_rescan_cycle(self, buggy_project: Path):
        """
        Integration test:
        1. Scan to find issues
        2. Apply rule-based fixes
        3. Rescan to verify score improved
        """
        config = DevNogConfig()

        # ---------------------------------------------------------------
        # Step 1: Initial scan
        # ---------------------------------------------------------------
        scanner = Scanner(project_path=buggy_project, config=config)
        initial_report = scanner.scan()

        assert len(initial_report.findings) > 0
        initial_score = initial_report.overall_score
        initial_count = len(initial_report.findings)

        # Verify we found the expected issue types
        check_ids = {f.check_id for f in initial_report.findings}
        # At least some of these should be present
        expected_checks = {"SEC-001", "SEC-006", "SEC-009", "SEC-012", "ERR-001", "ERR-007"}
        found_expected = check_ids & expected_checks
        assert len(found_expected) >= 3, f"Expected at least 3 of {expected_checks}, found {found_expected}"

        # ---------------------------------------------------------------
        # Step 2: Apply rule-based fixes
        # ---------------------------------------------------------------
        fixer = RuleBasedFixer()
        applier = FixApplier(project_path=buggy_project)
        fixes_applied = 0

        for finding in initial_report.findings:
            if finding.fix_type != FixType.RULE_BASED:
                continue
            if not finding.file:
                continue

            # Read the source for fix generation
            file_path = buggy_project / finding.file
            if not file_path.exists():
                continue

            source = file_path.read_text()
            proposal = fixer.try_fix(finding, source)

            if proposal is not None:
                # Fix the file path for the applier
                proposal.file = finding.file
                result = applier.apply(proposal)
                if result.success:
                    fixes_applied += 1

        assert fixes_applied >= 1, "Should have applied at least one fix"

        # ---------------------------------------------------------------
        # Step 3: Rescan
        # ---------------------------------------------------------------
        scanner2 = Scanner(project_path=buggy_project, config=config)
        rescan_report = scanner2.scan()

        rescan_score = rescan_report.overall_score
        rescan_count = len(rescan_report.findings)

        # ---------------------------------------------------------------
        # Step 4: Verify improvement
        # ---------------------------------------------------------------
        # Score should improve (or at least not get worse)
        assert rescan_score >= initial_score, (
            f"Score did not improve: {initial_score} -> {rescan_score}"
        )

        # Finding count should decrease
        assert rescan_count < initial_count, (
            f"Finding count did not decrease: {initial_count} -> {rescan_count}"
        )

    def test_undo_restores_original_score(self, buggy_project: Path):
        """
        Integration test:
        1. Scan
        2. Fix
        3. Undo fixes
        4. Rescan and verify score returned to original
        """
        config = DevNogConfig()

        # Initial scan
        scanner = Scanner(project_path=buggy_project, config=config)
        initial_report = scanner.scan()
        initial_score = initial_report.overall_score
        initial_findings = len(initial_report.findings)

        # Apply a fix
        fixer = RuleBasedFixer()
        applier = FixApplier(project_path=buggy_project)

        for finding in initial_report.findings:
            if finding.fix_type != FixType.RULE_BASED or not finding.file:
                continue
            file_path = buggy_project / finding.file
            if not file_path.exists():
                continue
            source = file_path.read_text()
            proposal = fixer.try_fix(finding, source)
            if proposal is not None:
                proposal.file = finding.file
                result = applier.apply(proposal)
                if result.success:
                    break  # Just fix one

        # Undo all
        undo_mgr = UndoManager(project_path=buggy_project)
        undo_results = undo_mgr.undo_last_session()
        assert len(undo_results) >= 1
        assert all(r.success for r in undo_results)

        # Rescan after undo
        scanner3 = Scanner(project_path=buggy_project, config=config)
        undo_report = scanner3.scan()

        # Score should be back to (approximately) the original
        # It may not be exactly the same if file paths changed,
        # but should be close
        assert abs(undo_report.overall_score - initial_score) <= 5, (
            f"Score after undo ({undo_report.overall_score}) "
            f"diverged from original ({initial_score})"
        )

    def test_scan_with_category_filter(self, buggy_project: Path):
        """Scanning with category filter should only return those categories."""
        config = DevNogConfig(
            scan=ScanConfig(categories=["security"])
        )
        scanner = Scanner(project_path=buggy_project, config=config)
        report = scanner.scan()

        for finding in report.findings:
            assert finding.category == Category.SECURITY

    def test_scan_with_ignore_specific_checks(self, buggy_project: Path):
        """Ignored checks should not appear in scan results."""
        config = DevNogConfig(
            scan=ScanConfig(ignore=["SEC-001", "SEC-006"])
        )
        scanner = Scanner(project_path=buggy_project, config=config)
        report = scanner.scan()

        check_ids = {f.check_id for f in report.findings}
        assert "SEC-001" not in check_ids
        assert "SEC-006" not in check_ids

    def test_score_categories_populated(self, buggy_project: Path):
        """Scan report should have per-category scores."""
        config = DevNogConfig()
        scanner = Scanner(project_path=buggy_project, config=config)
        report = scanner.scan()

        # Should have at least security and error_handling categories
        assert len(report.category_scores) > 0

        for key, cat_score in report.category_scores.items():
            assert 0 <= cat_score.score <= 100
            assert cat_score.max_score == 100

    def test_multiple_fix_cycles(self, buggy_project: Path):
        """Multiple fix cycles should progressively improve the score."""
        config = DevNogConfig()
        scores = []

        for cycle in range(3):
            scanner = Scanner(project_path=buggy_project, config=config)
            report = scanner.scan()
            scores.append(report.overall_score)

            if not report.findings:
                break

            fixer = RuleBasedFixer()
            applier = FixApplier(project_path=buggy_project)

            fixed_any = False
            for finding in report.findings:
                if finding.fix_type != FixType.RULE_BASED or not finding.file:
                    continue
                file_path = buggy_project / finding.file
                if not file_path.exists():
                    continue
                source = file_path.read_text()
                proposal = fixer.try_fix(finding, source)
                if proposal is not None:
                    proposal.file = finding.file
                    result = applier.apply(proposal)
                    if result.success:
                        fixed_any = True

            if not fixed_any:
                break

        # Scores should be non-decreasing (at least not getting worse)
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1], (
                f"Score decreased in cycle {i}: {scores[i-1]} -> {scores[i]}"
            )
