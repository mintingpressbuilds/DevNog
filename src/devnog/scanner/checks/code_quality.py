"""Code quality checks (CQ-001 through CQ-010)."""

from __future__ import annotations

import ast
import hashlib
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.scanner.checks.base import BaseCheck


class CQ001FunctionLength(BaseCheck):
    """Detect functions over 50 lines."""

    check_id = "CQ-001"
    category = Category.CODE_QUALITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Function too long"

    def __init__(self, max_length: int = 50):
        self.max_length = max_length

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.end_lineno and node.lineno:
                    length = node.end_lineno - node.lineno + 1
                    if length > self.max_length:
                        findings.append(self._make_finding(
                            message=f"Function '{node.name}' is {length} lines (max {self.max_length})",
                            file_path=file_path,
                            line=node.lineno,
                            end_line=node.end_lineno,
                            suggestion=f"Split '{node.name}' into smaller subfunctions",
                        ))
        return findings


class CQ002DeepNesting(BaseCheck):
    """Detect deeply nested code (>4 levels)."""

    check_id = "CQ-002"
    category = Category.CODE_QUALITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Deeply nested code"

    def __init__(self, max_depth: int = 4):
        self.max_depth = max_depth

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        self._check_depth(tree, 0, file_path, findings)
        return findings

    def _check_depth(
        self, node: ast.AST, depth: int, file_path: Path, findings: list[Finding]
    ) -> None:
        nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try)
        if isinstance(node, nesting_nodes):
            depth += 1
            if depth > self.max_depth:
                findings.append(self._make_finding(
                    message=f"Code nested {depth} levels deep (max {self.max_depth})",
                    file_path=file_path,
                    line=getattr(node, "lineno", None),
                    suggestion="Extract early returns or break into helper functions",
                ))
                return  # Don't report deeper nesting in same block

        for child in ast.iter_child_nodes(node):
            self._check_depth(child, depth, file_path, findings)


class CQ003DuplicateCode(BaseCheck):
    """Detect duplicate code blocks."""

    check_id = "CQ-003"
    category = Category.CODE_QUALITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Duplicate code blocks"

    def __init__(self, min_lines: int = 6):
        self.min_lines = min_lines

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        lines = source.splitlines()

        # Extract function bodies and compare hashes of normalized blocks
        blocks: dict[str, list[tuple[str, int]]] = defaultdict(list)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.end_lineno and node.lineno and node.body:
                    # Use body start (first statement) to exclude the def line
                    body_start = node.body[0].lineno - 1  # 0-indexed
                    body_end = node.end_lineno
                    length = body_end - body_start
                    if length >= self.min_lines:
                        body_lines = lines[body_start : body_end]
                        normalized = "\n".join(l.strip() for l in body_lines if l.strip())
                        block_hash = hashlib.md5(normalized.encode()).hexdigest()
                        blocks[block_hash].append((node.name, node.lineno))

        for block_hash, locations in blocks.items():
            if len(locations) > 1:
                names = ", ".join(f"'{name}'" for name, _ in locations)
                findings.append(self._make_finding(
                    message=f"Duplicate code in functions: {names}",
                    file_path=file_path,
                    line=locations[0][1],
                    suggestion="Extract shared logic into a common function",
                ))

        return findings


class CQ004UnusedImports(BaseCheck):
    """Detect unused imports."""

    check_id = "CQ-004"
    category = Category.CODE_QUALITY
    severity = Severity.INFO
    fix_type = FixType.RULE_BASED
    description = "Unused imports"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []

        # Collect all imported names
        imported_names: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imported_names[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                if node.names[0].name == "*":
                    continue  # Star imports handled by CQ-009
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno

        # Collect all name usages (excluding import nodes themselves)
        used_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                # Check the root of attribute access
                root = node
                while isinstance(root, ast.Attribute):
                    root = root.value  # type: ignore[assignment]
                if isinstance(root, ast.Name):
                    used_names.add(root.id)

        # Find unused
        for name, lineno in imported_names.items():
            if name not in used_names and name != "__all__":
                findings.append(self._make_finding(
                    message=f"Unused import: '{name}'",
                    file_path=file_path,
                    line=lineno,
                    suggestion=f"Remove unused import '{name}'",
                ))

        return findings


class CQ005MissingTypeHints(BaseCheck):
    """Detect missing type hints on public functions."""

    check_id = "CQ-005"
    category = Category.CODE_QUALITY
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "Missing type hints"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue  # Skip private functions

                missing_params = []
                for arg in node.args.args:
                    if arg.arg == "self" or arg.arg == "cls":
                        continue
                    if arg.annotation is None:
                        missing_params.append(arg.arg)

                has_return = node.returns is not None

                if missing_params or not has_return:
                    parts = []
                    if missing_params:
                        parts.append(f"params: {', '.join(missing_params)}")
                    if not has_return:
                        parts.append("return type")
                    findings.append(self._make_finding(
                        message=f"Missing type hints on '{node.name}': {'; '.join(parts)}",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=f"Add type annotations to '{node.name}'",
                    ))

        return findings


class CQ006MissingDocstrings(BaseCheck):
    """Detect missing docstrings on public functions."""

    check_id = "CQ-006"
    category = Category.CODE_QUALITY
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "Missing docstrings"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue

                docstring = ast.get_docstring(node)
                if not docstring:
                    findings.append(self._make_finding(
                        message=f"Missing docstring on public function '{node.name}'",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=f"Add a docstring to '{node.name}'",
                    ))

            elif isinstance(node, ast.ClassDef):
                if node.name.startswith("_"):
                    continue
                docstring = ast.get_docstring(node)
                if not docstring:
                    findings.append(self._make_finding(
                        message=f"Missing docstring on public class '{node.name}'",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=f"Add a docstring to '{node.name}'",
                    ))

        return findings


class CQ007HighComplexity(BaseCheck):
    """Detect high cyclomatic complexity (>10)."""

    check_id = "CQ-007"
    category = Category.CODE_QUALITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "High cyclomatic complexity"

    def __init__(self, max_complexity: int = 10):
        self.max_complexity = max_complexity

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = self._compute_complexity(node)
                if complexity > self.max_complexity:
                    findings.append(self._make_finding(
                        message=f"Function '{node.name}' has complexity {complexity} (max {self.max_complexity})",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=f"Simplify '{node.name}' by reducing branching",
                    ))
        return findings

    def _compute_complexity(self, node: ast.AST) -> int:
        """Compute cyclomatic complexity of a function."""
        complexity = 1  # Base complexity
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.Assert, ast.comprehension)):
                complexity += 1
        return complexity


class CQ008GlobalMutableState(BaseCheck):
    """Detect global mutable state."""

    check_id = "CQ-008"
    category = Category.CODE_QUALITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Global mutable state"

    MUTABLE_TYPES = {"list", "dict", "set", "List", "Dict", "Set"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if name.startswith("_") and name.isupper():
                            continue  # Skip private constants
                        if name.isupper():
                            continue  # Skip constants (convention)
                        if self._is_mutable(node.value):
                            findings.append(self._make_finding(
                                message=f"Global mutable state: '{name}'",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion=f"Refactor '{name}' to use parameter passing or class attributes",
                            ))
        return findings

    def _is_mutable(self, node: ast.AST) -> bool:
        """Check if a value expression creates a mutable object."""
        if isinstance(node, (ast.List, ast.Dict, ast.Set)):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in self.MUTABLE_TYPES:
                return True
            if isinstance(func, ast.Attribute) and func.attr in self.MUTABLE_TYPES:
                return True
        return False


class CQ009StarImports(BaseCheck):
    """Detect star imports (from X import *)."""

    check_id = "CQ-009"
    category = Category.CODE_QUALITY
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Star imports"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        module = node.module or "<unknown>"
                        findings.append(self._make_finding(
                            message=f"Star import: 'from {module} import *'",
                            file_path=file_path,
                            line=node.lineno,
                            suggestion=f"Replace with explicit imports from '{module}'",
                        ))
        return findings


class CQ010DeadCode(BaseCheck):
    """Detect dead code (unreachable branches)."""

    check_id = "CQ-010"
    category = Category.CODE_QUALITY
    severity = Severity.INFO
    fix_type = FixType.RULE_BASED
    description = "Dead code"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_unreachable(node, file_path, findings)
        return findings

    def _check_unreachable(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: Path,
        findings: list[Finding],
    ) -> None:
        """Check for code after return/raise/break/continue."""
        for node in ast.walk(func):
            body = None
            if hasattr(node, "body") and isinstance(node.body, list):
                body = node.body

            if body is None:
                continue

            for i, stmt in enumerate(body):
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    if i < len(body) - 1:
                        next_stmt = body[i + 1]
                        findings.append(self._make_finding(
                            message=f"Unreachable code after {type(stmt).__name__.lower()} statement",
                            file_path=file_path,
                            line=getattr(next_stmt, "lineno", None),
                            suggestion="Remove unreachable code",
                        ))
                        break
