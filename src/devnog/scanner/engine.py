"""Scanner engine — orchestrates all checks and produces reports."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.config import DevNogConfig, load_config
from devnog.core.models import Category, Finding, ScanReport
from devnog.scanner.checks import ALL_CHECKS
from devnog.scanner.checks.base import BaseCheck, DependencyCheck
from devnog.scanner.scoring import compute_scores


class Scanner:
    """Main scanner that runs all checks on a codebase."""

    def __init__(
        self,
        project_path: Path | None = None,
        config: DevNogConfig | None = None,
    ):
        self.project_path = (project_path or Path.cwd()).resolve()
        self.config = config or load_config(self.project_path)

        # Initialize checks
        self.ast_checks: list[BaseCheck] = []
        self.dep_checks: list[DependencyCheck] = []

        for check_cls in ALL_CHECKS:
            if issubclass(check_cls, DependencyCheck):
                self.dep_checks.append(check_cls())
            elif issubclass(check_cls, BaseCheck):
                check = check_cls()
                # Apply config overrides
                if check.check_id.startswith("CQ-001"):
                    check = check_cls(max_length=self.config.scan.max_function_length)  # type: ignore[call-arg]
                elif check.check_id.startswith("CQ-002"):
                    check = check_cls(max_depth=self.config.scan.max_nesting_depth)  # type: ignore[call-arg]
                elif check.check_id.startswith("CQ-007"):
                    check = check_cls(max_complexity=self.config.scan.max_complexity)  # type: ignore[call-arg]
                else:
                    check = check_cls()
                self.ast_checks.append(check)

    def scan(self, target_path: Path | None = None) -> ScanReport:
        """Run all checks and produce a scan report."""
        scan_path = target_path or self.project_path
        findings: list[Finding] = []
        total_lines = 0
        total_files = 0

        # Collect Python files
        py_files = self._collect_python_files(scan_path)
        total_files = len(py_files)

        # Run AST-based checks on each file
        for py_file in py_files:
            try:
                source = py_file.read_text(errors="ignore")
                total_lines += len(source.splitlines())

                tree = ast.parse(source, filename=str(py_file))

                for check in self.ast_checks:
                    if check.check_id in self.config.scan.ignore:
                        continue

                    category_key = {
                        Category.CODE_QUALITY: "code_quality",
                        Category.SECURITY: "security",
                        Category.ERROR_HANDLING: "error_handling",
                    }.get(check.category, "")

                    if category_key and category_key not in self.config.scan.categories:
                        continue

                    try:
                        file_findings = check.run(py_file, source, tree)
                        # Make paths relative to project root for display
                        for f in file_findings:
                            if f.file:
                                try:
                                    f.file = f.file.relative_to(self.project_path)
                                except ValueError:
                                    pass  # path is not relative to project root; keep as-is
                        findings.extend(file_findings)
                    except Exception:
                        continue  # Don't fail entire scan if one check errors

            except (SyntaxError, UnicodeDecodeError):
                continue

        # Run dependency checks
        if "dependencies" in self.config.scan.categories:
            for check in self.dep_checks:
                if check.check_id in self.config.scan.ignore:
                    continue
                try:
                    dep_findings = check.run(scan_path)
                    findings.extend(dep_findings)
                except Exception:
                    continue

        # Compute scores
        overall_score, category_scores = compute_scores(findings)

        # Build report
        report = ScanReport(
            overall_score=overall_score,
            category_scores=category_scores,
            findings=findings,
            total_lines=total_lines,
            total_files=total_files,
            project_name=self.project_path.name,
        )

        return report

    def _collect_python_files(self, path: Path) -> list[Path]:
        """Collect all Python files, excluding configured patterns."""
        py_files: list[Path] = []

        if path.is_file() and path.suffix == ".py":
            return [path]

        for py_file in path.rglob("*.py"):
            # Check exclusions
            rel = str(py_file.relative_to(path))
            if any(excl.rstrip("/") in rel for excl in self.config.exclude):
                continue
            py_files.append(py_file)

        return sorted(py_files)
