"""Base check class for all scanner checks."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity


class BaseCheck(ABC):
    """Abstract base class for all scanner checks."""

    check_id: str = ""
    category: Category = Category.CODE_QUALITY
    severity: Severity = Severity.INFO
    fix_type: FixType = FixType.MANUAL
    description: str = ""

    @abstractmethod
    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        """Run the check on a single file. Return list of findings."""
        ...

    def _make_finding(
        self,
        message: str,
        file_path: Path,
        line: int | None = None,
        end_line: int | None = None,
        code_snippet: str = "",
        suggestion: str = "",
        severity: Severity | None = None,
        fix_type: FixType | None = None,
    ) -> Finding:
        """Helper to create a Finding with this check's defaults."""
        return Finding(
            check_id=self.check_id,
            category=self.category,
            severity=severity or self.severity,
            message=message,
            file=file_path,
            line=line,
            end_line=end_line,
            code_snippet=code_snippet,
            fix_type=fix_type or self.fix_type,
            suggestion=suggestion,
        )


class DependencyCheck(ABC):
    """Base class for dependency-based checks (don't use AST)."""

    check_id: str = ""
    category: Category = Category.DEPENDENCIES
    severity: Severity = Severity.WARNING
    fix_type: FixType = FixType.MANUAL
    description: str = ""

    @abstractmethod
    def run(self, project_path: Path) -> list[Finding]:
        """Run the check on project dependencies. Return list of findings."""
        ...

    def _make_finding(
        self,
        message: str,
        file_path: Path | None = None,
        line: int | None = None,
        suggestion: str = "",
        severity: Severity | None = None,
        fix_type: FixType | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            category=self.category,
            severity=severity or self.severity,
            message=message,
            file=file_path,
            line=line,
            fix_type=fix_type or self.fix_type,
            suggestion=suggestion,
        )
