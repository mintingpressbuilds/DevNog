"""Score computation for scanner results."""

from __future__ import annotations

from devnog.core.models import Category, CategoryScore, Finding, Severity


# Deduction points per severity
DEDUCTIONS = {
    Severity.CRITICAL: 15,
    Severity.WARNING: 5,
    Severity.INFO: 1,
}

# Category weights for overall score
WEIGHTS = {
    "security": 0.25,
    "error_handling": 0.25,
    "code_quality": 0.20,
    "dependencies": 0.15,
    "test_coverage": 0.15,
}

# Map finding categories to score category keys
CATEGORY_MAP = {
    Category.SECURITY: "security",
    Category.ERROR_HANDLING: "error_handling",
    Category.CODE_QUALITY: "code_quality",
    Category.DEPENDENCIES: "dependencies",
    Category.TEST_COVERAGE: "test_coverage",
    Category.PROD_READINESS: "prod_readiness",
}


def compute_scores(findings: list[Finding]) -> tuple[int, dict[str, CategoryScore]]:
    """
    Compute category scores and overall score from findings.

    Each category starts at 100.
    Deductions: critical=-15, warning=-5, info=-1.
    Floor at 0.
    Overall score = weighted average of category scores.
    """
    # Group findings by category
    category_findings: dict[str, list[Finding]] = {
        "security": [],
        "error_handling": [],
        "code_quality": [],
        "dependencies": [],
    }

    for finding in findings:
        key = CATEGORY_MAP.get(finding.category)
        if key and key in category_findings:
            category_findings[key].append(finding)

    # Compute per-category scores
    category_scores: dict[str, CategoryScore] = {}
    for key, cat_findings in category_findings.items():
        score = 100
        for f in cat_findings:
            score -= DEDUCTIONS.get(f.severity, 0)
        score = max(0, score)

        cat_enum = None
        for c, k in CATEGORY_MAP.items():
            if k == key:
                cat_enum = c
                break

        category_scores[key] = CategoryScore(
            category=cat_enum or Category.CODE_QUALITY,
            score=score,
            findings=cat_findings,
        )

    # Compute overall score (weighted average)
    total_weight = 0.0
    weighted_sum = 0.0

    for key, weight in WEIGHTS.items():
        if key in category_scores:
            weighted_sum += category_scores[key].score * weight
            total_weight += weight

    if total_weight > 0:
        overall = round(weighted_sum / total_weight)
    else:
        overall = 100

    return overall, category_scores
