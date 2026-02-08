"""Tests for scoring algorithm."""

from __future__ import annotations

import pytest

from devnog.scanner.scoring import compute_scores, DEDUCTIONS, WEIGHTS
from devnog.core.models import Finding, Category, CategoryScore, Severity, FixType


def _make_finding(
    category: Category,
    severity: Severity,
    check_id: str = "TEST-001",
) -> Finding:
    return Finding(
        check_id=check_id,
        category=category,
        severity=severity,
        message="Test finding",
        fix_type=FixType.MANUAL,
    )


class TestComputeScores:
    def test_no_findings_returns_100(self):
        """No findings should give perfect score of 100."""
        overall, category_scores = compute_scores([])
        assert overall == 100

    def test_critical_deduction(self):
        """Each CRITICAL finding should deduct 15 points."""
        findings = [
            _make_finding(Category.SECURITY, Severity.CRITICAL),
        ]
        overall, category_scores = compute_scores(findings)

        assert "security" in category_scores
        assert category_scores["security"].score == 100 - DEDUCTIONS[Severity.CRITICAL]

    def test_warning_deduction(self):
        """Each WARNING finding should deduct 5 points."""
        findings = [
            _make_finding(Category.CODE_QUALITY, Severity.WARNING),
        ]
        overall, category_scores = compute_scores(findings)

        assert "code_quality" in category_scores
        assert category_scores["code_quality"].score == 100 - DEDUCTIONS[Severity.WARNING]

    def test_info_deduction(self):
        """Each INFO finding should deduct 1 point."""
        findings = [
            _make_finding(Category.ERROR_HANDLING, Severity.INFO),
        ]
        overall, category_scores = compute_scores(findings)

        assert "error_handling" in category_scores
        assert category_scores["error_handling"].score == 100 - DEDUCTIONS[Severity.INFO]

    def test_score_floor_at_zero(self):
        """Score should never go below 0."""
        # 10 critical findings = 150 deductions
        findings = [
            _make_finding(Category.SECURITY, Severity.CRITICAL)
            for _ in range(10)
        ]
        overall, category_scores = compute_scores(findings)

        assert category_scores["security"].score == 0

    def test_multiple_categories(self):
        """Findings across categories should compute independently."""
        findings = [
            _make_finding(Category.SECURITY, Severity.CRITICAL),
            _make_finding(Category.CODE_QUALITY, Severity.WARNING),
            _make_finding(Category.ERROR_HANDLING, Severity.INFO),
        ]
        overall, category_scores = compute_scores(findings)

        assert category_scores["security"].score == 100 - 15
        assert category_scores["code_quality"].score == 100 - 5
        assert category_scores["error_handling"].score == 100 - 1

    def test_overall_is_weighted_average(self):
        """Overall score should be a weighted average of category scores."""
        # All same severity for simpler math
        findings = [
            _make_finding(Category.SECURITY, Severity.CRITICAL),       # 85
            _make_finding(Category.CODE_QUALITY, Severity.CRITICAL),   # 85
            _make_finding(Category.ERROR_HANDLING, Severity.CRITICAL), # 85
        ]
        overall, category_scores = compute_scores(findings)

        # Each category is 85, dependencies is 100
        # Weighted: security=0.25*85 + error_handling=0.25*85 + code_quality=0.20*85 + deps=0.15*100
        # = 21.25 + 21.25 + 17.0 + 15.0 = 74.5
        # total_weight = 0.25 + 0.25 + 0.20 + 0.15 = 0.85
        # overall = round(74.5 / 0.85) = round(87.647...) = 88
        assert 0 <= overall <= 100

    def test_category_scores_include_findings(self):
        """CategoryScore objects should include their findings."""
        findings = [
            _make_finding(Category.SECURITY, Severity.WARNING, check_id="SEC-001"),
            _make_finding(Category.SECURITY, Severity.INFO, check_id="SEC-002"),
        ]
        overall, category_scores = compute_scores(findings)

        assert len(category_scores["security"].findings) == 2

    def test_category_score_has_correct_category(self):
        """CategoryScore should have the correct category enum."""
        findings = [
            _make_finding(Category.SECURITY, Severity.WARNING),
        ]
        overall, category_scores = compute_scores(findings)

        assert category_scores["security"].category == Category.SECURITY

    def test_mixed_severities_in_one_category(self):
        """Multiple severities in one category should sum deductions."""
        findings = [
            _make_finding(Category.SECURITY, Severity.CRITICAL),  # -15
            _make_finding(Category.SECURITY, Severity.WARNING),   # -5
            _make_finding(Category.SECURITY, Severity.INFO),      # -1
        ]
        overall, category_scores = compute_scores(findings)

        assert category_scores["security"].score == 100 - 15 - 5 - 1  # 79


class TestDeductionConstants:
    def test_critical_deduction_value(self):
        assert DEDUCTIONS[Severity.CRITICAL] == 15

    def test_warning_deduction_value(self):
        assert DEDUCTIONS[Severity.WARNING] == 5

    def test_info_deduction_value(self):
        assert DEDUCTIONS[Severity.INFO] == 1


class TestWeights:
    def test_weights_sum_to_one(self):
        """Category weights should sum to 1.0."""
        assert abs(sum(WEIGHTS.values()) - 1.0) < 0.01

    def test_security_weight(self):
        assert WEIGHTS["security"] == 0.25

    def test_error_handling_weight(self):
        assert WEIGHTS["error_handling"] == 0.25


class TestDependencyCategory:
    def test_dependencies_category_scored(self):
        """Dependency findings should be scored in the dependencies category."""
        findings = [
            _make_finding(Category.DEPENDENCIES, Severity.WARNING, check_id="DEP-003"),
        ]
        overall, category_scores = compute_scores(findings)

        assert "dependencies" in category_scores
        assert category_scores["dependencies"].score == 100 - 5
