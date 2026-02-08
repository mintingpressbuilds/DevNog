"""Error handling checks (ERR-001 through ERR-008)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.scanner.checks.base import BaseCheck


class ERR001BareExcept(BaseCheck):
    """Detect bare except clauses."""

    check_id = "ERR-001"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Bare except clause"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    findings.append(self._make_finding(
                        message="Bare except: catches all exceptions including SystemExit and KeyboardInterrupt",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Replace with 'except Exception as e:'",
                    ))
        return findings


class ERR002SilentExcept(BaseCheck):
    """Detect except: pass (silenced exceptions)."""

    check_id = "ERR-002"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Silent exception (except: pass)"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    findings.append(self._make_finding(
                        message="Silent exception: 'except: pass' hides errors",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Replace with 'except Exception as e: logger.exception(e)'",
                    ))
                # Also catch '...' (Ellipsis) as pass equivalent
                elif (len(node.body) == 1 and isinstance(node.body[0], ast.Expr)
                      and isinstance(node.body[0].value, ast.Constant)
                      and node.body[0].value.value is ...):
                    findings.append(self._make_finding(
                        message="Silent exception: 'except: ...' hides errors",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Replace with proper error logging",
                    ))
        return findings


class ERR003IOWithoutTry(BaseCheck):
    """Detect I/O operations without try/except."""

    check_id = "ERR-003"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "I/O without error handling"

    IO_CALLS = {"open", "read", "write", "read_text", "write_text", "read_bytes", "write_bytes"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        # Track which lines are inside try blocks
        try_ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                end = node.end_lineno or node.lineno
                try_ranges.append((node.lineno, end))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in self.IO_CALLS:
                    line = node.lineno
                    in_try = any(start <= line <= end for start, end in try_ranges)
                    if not in_try:
                        findings.append(self._make_finding(
                            message=f"I/O operation '{func_name}()' without error handling",
                            file_path=file_path,
                            line=line,
                            suggestion="Wrap in try/except with appropriate error handling",
                        ))
        return findings


class ERR004APIWithoutTry(BaseCheck):
    """Detect external API calls without try/except."""

    check_id = "ERR-004"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "API call without error handling"

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}
    HTTP_LIBS = {"requests", "httpx", "aiohttp", "urllib"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        try_ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                end = node.end_lineno or node.lineno
                try_ranges.append((node.lineno, end))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    method = node.func.attr
                    if method in self.HTTP_METHODS:
                        # Check if the object looks like an HTTP library
                        obj_name = ""
                        if isinstance(node.func.value, ast.Name):
                            obj_name = node.func.value.id
                        elif isinstance(node.func.value, ast.Attribute):
                            obj_name = node.func.value.attr

                        is_http = obj_name.lower() in self.HTTP_LIBS or method in self.HTTP_METHODS
                        if is_http:
                            line = node.lineno
                            in_try = any(start <= line <= end for start, end in try_ranges)
                            if not in_try:
                                findings.append(self._make_finding(
                                    message=f"External API call '{obj_name}.{method}()' without error handling",
                                    file_path=file_path,
                                    line=line,
                                    suggestion="Wrap in try/except with retry logic and error handling",
                                ))
        return findings


class ERR005NoGlobalHandler(BaseCheck):
    """Detect missing global exception handler."""

    check_id = "ERR-005"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "No global exception handler"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        # Only check main/entry point files
        filename = file_path.name
        if filename not in ("main.py", "app.py", "application.py", "wsgi.py", "asgi.py", "__main__.py"):
            return findings

        has_global_handler = False
        source_lower = source.lower()

        # Check for common global handler patterns
        patterns = [
            "exception_handler",
            "errorhandler",
            "error_handler",
            "sys.excepthook",
            "middleware",
            "@app.exception",
            "add_exception_handler",
        ]
        for pattern in patterns:
            if pattern in source_lower:
                has_global_handler = True
                break

        # Check for if __name__ == "__main__" with try/except
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Compare):
                    if isinstance(test.left, ast.Name) and test.left.id == "__name__":
                        # Check if body has try/except
                        for child in ast.walk(node):
                            if isinstance(child, ast.Try):
                                has_global_handler = True
                                break

        if not has_global_handler:
            findings.append(self._make_finding(
                message="No global exception handler configured",
                file_path=file_path,
                line=1,
                suggestion="Add a global exception handler appropriate for your framework",
            ))

        return findings


class ERR006AsyncNoCancelHandler(BaseCheck):
    """Detect async functions missing CancelledError handling."""

    check_id = "ERR-006"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Async missing cancellation handling"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                has_cancel_handler = False
                has_try = False

                for child in ast.walk(node):
                    if isinstance(child, ast.Try):
                        has_try = True
                    if isinstance(child, ast.ExceptHandler):
                        if child.type and isinstance(child.type, ast.Name):
                            if child.type.id in ("CancelledError", "asyncio.CancelledError"):
                                has_cancel_handler = True
                        elif child.type and isinstance(child.type, ast.Attribute):
                            if child.type.attr == "CancelledError":
                                has_cancel_handler = True

                # Only flag if the function has try blocks but no cancel handler
                if has_try and not has_cancel_handler:
                    # Check if the function does I/O or long operations
                    body_src = ast.dump(node)
                    if any(kw in body_src for kw in ("await", "sleep", "gather")):
                        findings.append(self._make_finding(
                            message=f"Async function '{node.name}' lacks CancelledError handling",
                            file_path=file_path,
                            line=node.lineno,
                            suggestion="Add except asyncio.CancelledError handler for cleanup",
                        ))

        return findings


class ERR007HTTPNoTimeout(BaseCheck):
    """Detect HTTP calls without timeout parameter."""

    check_id = "ERR-007"
    category = Category.ERROR_HANDLING
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "HTTP call without timeout"

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in self.HTTP_METHODS:
                    # Check if timeout is provided
                    has_timeout = any(
                        kw.arg == "timeout" for kw in node.keywords
                    )
                    if not has_timeout:
                        obj_name = ""
                        if isinstance(node.func.value, ast.Name):
                            obj_name = node.func.value.id

                        # Only flag for known HTTP libraries
                        if obj_name.lower() in ("requests", "httpx", "session", "client"):
                            findings.append(self._make_finding(
                                message=f"HTTP call '{obj_name}.{node.func.attr}()' without timeout",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Add timeout=30 parameter",
                            ))
        return findings


class ERR008ReturnNoneOnError(BaseCheck):
    """Detect functions that return None on error instead of raising."""

    check_id = "ERR-008"
    category = Category.ERROR_HANDLING
    severity = Severity.INFO
    fix_type = FixType.RULE_BASED
    description = "Returns None on error"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                # Check if the handler returns None
                for child in node.body:
                    if isinstance(child, ast.Return):
                        if child.value is None:
                            findings.append(self._make_finding(
                                message="Returns None on error — hides failure from caller",
                                file_path=file_path,
                                line=child.lineno,
                                suggestion="Re-raise the exception or return a meaningful error",
                            ))
                        elif isinstance(child.value, ast.Constant) and child.value.value is None:
                            findings.append(self._make_finding(
                                message="Returns None on error — hides failure from caller",
                                file_path=file_path,
                                line=child.lineno,
                                suggestion="Re-raise the exception or return a meaningful error",
                            ))
        return findings
