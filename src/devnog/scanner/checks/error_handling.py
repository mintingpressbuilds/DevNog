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
                # Only flag as "silent" if the except body is just pass/Ellipsis.
                # If the exception type is specific (e.g., except ValueError: pass),
                # it's typically an intentional suppression — still flag but as INFO.
                is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
                is_ellipsis = (
                    len(node.body) == 1
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and node.body[0].value.value is ...
                )
                if not (is_pass or is_ellipsis):
                    continue

                # Typed except: pass (e.g., except ValueError: pass) is intentional
                # suppression — skip it entirely. Only flag bare except: pass.
                if node.type is not None:
                    continue

                desc = "pass" if is_pass else "..."
                findings.append(self._make_finding(
                    message=f"Silent exception: 'except: {desc}' hides errors",
                    file_path=file_path,
                    line=node.lineno,
                    suggestion="Replace with 'except Exception as e: logger.exception(e)'",
                ))
        return findings


class ERR003IOWithoutTry(BaseCheck):
    """Detect I/O operations without try/except."""

    check_id = "ERR-003"
    category = Category.ERROR_HANDLING
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "I/O without error handling"

    # Only flag bare open() — Path methods raise descriptive errors on their own
    IO_FUNCTIONS = {"open"}  # Builtins called as bare names
    IO_METHODS: set[str] = set()  # Path methods are safe without explicit try

    # Route handler decorators that indicate user-facing code
    ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_view"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []

        # Only flag I/O in web route handlers where user input may cause errors.
        # Internal library code is trusted to handle errors appropriately.
        route_funcs: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                        elif isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                    if dec_name in self.ROUTE_DECORATORS:
                        if node.end_lineno:
                            for line in range(node.lineno, node.end_lineno + 1):
                                route_funcs.add(line)

        # Track which lines are inside try blocks
        try_ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                end = node.end_lineno or node.lineno
                try_ranges.append((node.lineno, end))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                is_io = False
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    is_io = func_name in self.IO_FUNCTIONS
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    is_io = func_name in self.IO_METHODS

                if is_io:
                    line = node.lineno
                    # Only flag in route handlers
                    if line not in route_funcs:
                        continue
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

                        is_http = obj_name.lower() in self.HTTP_LIBS
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
    severity = Severity.INFO
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

        # CLI frameworks (Click, Typer, argparse) handle exceptions internally
        cli_patterns = ["click", "typer", "argparse"]
        for pattern in cli_patterns:
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
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "Async missing cancellation handling"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []

        # Build set of nested (inner) async functions to skip
        nested_async: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if child is node:
                        continue
                    if isinstance(child, ast.AsyncFunctionDef):
                        nested_async.add(child.lineno)

        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                # Skip nested async functions (wrappers, closures)
                if node.lineno in nested_async:
                    continue

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

                # Only flag if the function has try blocks but no cancel handler,
                # AND the function directly uses await on long-running operations
                if has_try and not has_cancel_handler:
                    has_long_await = False
                    for child in ast.walk(node):
                        if isinstance(child, ast.Await):
                            # Check if awaiting sleep, gather, or other long ops
                            if isinstance(child.value, ast.Call):
                                call = child.value
                                name = ""
                                if isinstance(call.func, ast.Attribute):
                                    name = call.func.attr
                                elif isinstance(call.func, ast.Name):
                                    name = call.func.id
                                if name in ("sleep", "gather", "wait", "wait_for"):
                                    has_long_await = True
                                    break

                    if has_long_await:
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

        # Build map of function return annotations to skip Optional/None returns
        func_returns: dict[tuple[int, int], bool] = {}  # (start, end) -> is_optional
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = node.end_lineno or node.lineno
                is_optional = False
                if node.returns:
                    ret_src = ast.dump(node.returns)
                    if "None" in ret_src or "Optional" in ret_src:
                        is_optional = True
                # Functions without return annotation may intentionally return None
                if node.returns is None:
                    is_optional = True
                func_returns[(node.lineno, end)] = is_optional

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                # Check if this handler is inside a function that's Optional
                handler_line = node.lineno
                in_optional_func = any(
                    start <= handler_line <= end and is_opt
                    for (start, end), is_opt in func_returns.items()
                )
                if in_optional_func:
                    continue

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
