"""Base class for all QA Gate checks."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity


class QACheck(ABC):
    """Abstract base class for all QA gate checks.

    Each concrete check must define:
      - check_id   : unique identifier (e.g. "QA-001")
      - category   : Category.PROD_READINESS for all QA checks
      - severity   : Severity.CRITICAL | WARNING | INFO
      - fix_type   : how the finding can be resolved
      - description: short human-readable description of what is checked

    The ``run`` method receives the project root and a pre-parsed list of
    source files so that each check can iterate over the entire project in a
    single pass.
    """

    check_id: str = ""
    category: Category = Category.PROD_READINESS
    severity: Severity = Severity.WARNING
    fix_type: FixType = FixType.MANUAL
    description: str = ""

    # Whether a failure of this check should block deployment.
    required: bool = False

    @abstractmethod
    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        """Run the check across the whole project.

        Parameters
        ----------
        project_path:
            Root directory of the project being analysed.
        source_files:
            Pre-parsed Python files as ``(file_path, source_text, ast_tree)``
            tuples.

        Returns
        -------
        list[Finding]
            Zero or more findings produced by this check.
        """
        ...

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        message: str,
        file_path: Path | None = None,
        line: int | None = None,
        end_line: int | None = None,
        code_snippet: str = "",
        suggestion: str = "",
        severity: Severity | None = None,
        fix_type: FixType | None = None,
    ) -> Finding:
        """Create a :class:`Finding` pre-populated with this check's defaults."""
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

    def _get_try_ranges(self, tree: ast.AST) -> list[tuple[int, int]]:
        """Return ``(start_line, end_line)`` for every ``try`` block in *tree*."""
        ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                end = node.end_lineno or node.lineno
                ranges.append((node.lineno, end))
        return ranges

    def _line_inside_try(self, line: int, try_ranges: list[tuple[int, int]]) -> bool:
        return any(start <= line <= end for start, end in try_ranges)
