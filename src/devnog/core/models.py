"""Shared data models used across DevNog modules."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


class Severity(enum.Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Category(enum.Enum):
    CODE_QUALITY = "code_quality"
    SECURITY = "security"
    ERROR_HANDLING = "error_handling"
    DEPENDENCIES = "dependencies"
    TEST_COVERAGE = "test_coverage"
    PROD_READINESS = "prod_readiness"


class FixType(enum.Enum):
    RULE_BASED = "rule_based"
    AI_GENERATED = "ai_generated"
    MANUAL = "manual"


@dataclass
class Finding:
    """A single issue found by the scanner or QA gate."""

    check_id: str
    category: Category
    severity: Severity
    message: str
    file: Path | None = None
    line: int | None = None
    end_line: int | None = None
    code_snippet: str = ""
    fix_type: FixType = FixType.MANUAL
    suggestion: str = ""

    @property
    def is_auto_fixable(self) -> bool:
        return self.fix_type == FixType.RULE_BASED

    @property
    def is_ai_fixable(self) -> bool:
        return self.fix_type == FixType.AI_GENERATED


@dataclass
class CategoryScore:
    """Score for a single category."""

    category: Category
    score: int
    max_score: int = 100
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ScanReport:
    """Complete scan report with scores and findings."""

    overall_score: int
    category_scores: dict[str, CategoryScore] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    total_lines: int = 0
    total_files: int = 0
    total_dependencies: int = 0
    scanned_at: datetime = field(default_factory=datetime.now)
    project_name: str = ""
    project_version: str = ""
    source_type: str = "directory"
    is_temp: bool = False

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def auto_fixable_count(self) -> int:
        return sum(1 for f in self.findings if f.is_auto_fixable)

    @property
    def ai_fixable_count(self) -> int:
        return sum(1 for f in self.findings if f.is_ai_fixable)

    @property
    def manual_count(self) -> int:
        return sum(1 for f in self.findings if f.fix_type == FixType.MANUAL)


@dataclass
class FixProposal:
    """A proposed fix for an issue."""

    finding_id: str
    fix_type: str
    description: str
    diff: str
    file: Path
    line_start: int
    line_end: int
    new_code: str
    manual_steps: list[str] = field(default_factory=list)
    confidence: str = "high"
    confidence_score: float = 1.0
    confidence_reason: str = ""
    side_effects: list[str] = field(default_factory=list)
    requires_review: bool = False
    original_code: str = ""


@dataclass
class FixResult:
    """Result of applying a fix."""

    success: bool
    message: str
    file: Path | None = None
    lines_changed: int = 0
    manual_steps: list[str] = field(default_factory=list)
    finding_id: str = ""
    applied_at: datetime = field(default_factory=datetime.now)


@dataclass
class RuntimeFixContext:
    """Context from a runtime failure capture for targeted fixes."""

    error_type: str
    error_message: str
    traceback: str
    file: Path
    line: int
    function_args: dict = field(default_factory=dict)
    local_variables: dict = field(default_factory=dict)
    checkpoint_history: list[dict] = field(default_factory=list)
    occurrence_count: int = 1
    occurrence_pattern: str = ""


@dataclass
class QAVerdict:
    """QA Gate verdict."""

    verdict: str  # "PASS", "CONDITIONAL PASS", "FAIL"
    score: int
    passed_checks: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)
    failures: list[Finding] = field(default_factory=list)
