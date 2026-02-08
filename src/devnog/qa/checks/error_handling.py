"""QA checks for production error-handling robustness (QA-001 through QA-003)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck

# ------------------------------------------------------------------
# Entry-point file names where a top-level handler is expected.
# ------------------------------------------------------------------
_ENTRY_POINT_NAMES = frozenset({
    "main.py",
    "app.py",
    "application.py",
    "wsgi.py",
    "asgi.py",
    "__main__.py",
    "manage.py",
    "server.py",
    "cli.py",
})


class QA001UnhandledEntryPointExceptions(QACheck):
    """Detect entry-point modules that lack a top-level exception handler.

    Production services must ensure that unexpected exceptions are caught at
    the outermost layer so that they can be logged, reported and the process
    can shut down gracefully rather than crashing with an unformatted
    traceback.
    """

    check_id = "QA-001"
    category = Category.PROD_READINESS
    severity = Severity.CRITICAL
    fix_type = FixType.AI_GENERATED
    description = "Entry point lacks top-level exception handling"
    required = True

    _HANDLER_MARKERS = (
        "sys.excepthook",
        "exception_handler",
        "errorhandler",
        "error_handler",
        "add_exception_handler",
        "@app.exception",
    )

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            if file_path.name not in _ENTRY_POINT_NAMES:
                continue

            if self._has_global_handler(source, tree):
                continue

            findings.append(self._make_finding(
                message=(
                    f"Entry-point '{file_path.name}' has no top-level exception "
                    "handler — unhandled errors will crash the process"
                ),
                file_path=file_path,
                line=1,
                suggestion=(
                    "Wrap the main execution path in a try/except that logs "
                    "the error and exits with a non-zero code, or register "
                    "sys.excepthook / framework-level error middleware."
                ),
            ))

        return findings

    # ------------------------------------------------------------------

    def _has_global_handler(self, source: str, tree: ast.Module) -> bool:
        source_lower = source.lower()
        for marker in self._HANDLER_MARKERS:
            if marker in source_lower:
                return True

        # Check for ``if __name__ == "__main__":`` guarded by try/except.
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            if self._is_name_main_guard(node):
                for child in ast.walk(node):
                    if isinstance(child, ast.Try):
                        return True

        # Check for module-level try wrapping most of the body.
        for stmt in tree.body:
            if isinstance(stmt, ast.Try):
                return True

        return False

    @staticmethod
    def _is_name_main_guard(node: ast.If) -> bool:
        test = node.test
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
            if test.left.id == "__name__":
                for comparator in test.comparators:
                    if isinstance(comparator, ast.Constant) and comparator.value == "__main__":
                        return True
        return False


class QA002MissingRetryOnExternalCalls(QACheck):
    """Detect external service calls that have no retry/back-off logic.

    Transient network errors are inevitable in distributed systems.  Without
    retries, every blip turns into a user-visible failure.
    """

    check_id = "QA-002"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "External service call lacks retry logic"

    _HTTP_METHODS = frozenset({
        "get", "post", "put", "delete", "patch", "head", "options", "request",
    })
    _HTTP_LIBS = frozenset({
        "requests", "httpx", "aiohttp", "urllib", "session", "client",
    })
    _RETRY_MARKERS = frozenset({
        "retry", "tenacity", "backoff", "retrying", "urllib3.util.retry",
        "Retry", "retry_on_exception", "with_retries",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            # Quick check: if the file already imports a retry library, skip.
            if any(marker in source for marker in self._RETRY_MARKERS):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute):
                    continue

                method = node.func.attr
                if method not in self._HTTP_METHODS:
                    continue

                obj_name = self._resolve_obj_name(node.func.value)
                if obj_name.lower() not in self._HTTP_LIBS:
                    continue

                # Check enclosing function for a retry decorator.
                if self._call_inside_retry_decorated(node, tree):
                    continue

                findings.append(self._make_finding(
                    message=(
                        f"External call '{obj_name}.{method}()' has no retry "
                        "logic — transient failures will propagate directly"
                    ),
                    file_path=file_path,
                    line=node.lineno,
                    suggestion=(
                        "Add retry/back-off using tenacity, backoff, or "
                        "urllib3.util.retry.Retry"
                    ),
                ))

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_obj_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _call_inside_retry_decorated(
        self, call_node: ast.Call, tree: ast.Module
    ) -> bool:
        """Return True if the call lives inside a function with a retry decorator."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not (
                node.lineno <= call_node.lineno
                and (node.end_lineno or node.lineno) >= call_node.lineno
            ):
                continue
            for deco in node.decorator_list:
                deco_src = ast.dump(deco)
                if any(m in deco_src for m in ("retry", "backoff", "Retry")):
                    return True
        return False


class QA003CatchAllWithoutReraise(QACheck):
    """Detect ``except Exception`` blocks that swallow errors without re-raising.

    Catching ``Exception`` is sometimes necessary, but silently continuing
    masks bugs and makes debugging in production extremely difficult.
    """

    check_id = "QA-003"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Catch-all exception handler swallows errors"

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, _source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                if not self._catches_broad_exception(node):
                    continue
                if self._body_reraised(node):
                    continue
                if self._body_logs_error(node):
                    continue

                findings.append(self._make_finding(
                    message=(
                        "Broad except handler swallows the exception without "
                        "re-raising or logging"
                    ),
                    file_path=file_path,
                    line=node.lineno,
                    suggestion=(
                        "At minimum log the exception with logger.exception(), "
                        "or re-raise after cleanup."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _catches_broad_exception(handler: ast.ExceptHandler) -> bool:
        if handler.type is None:
            return True  # bare except
        if isinstance(handler.type, ast.Name) and handler.type.id in (
            "Exception", "BaseException",
        ):
            return True
        return False

    @staticmethod
    def _body_reraised(handler: ast.ExceptHandler) -> bool:
        for child in ast.walk(handler):
            if isinstance(child, ast.Raise):
                return True
        return False

    @staticmethod
    def _body_logs_error(handler: ast.ExceptHandler) -> bool:
        for child in ast.walk(handler):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in (
                        "exception", "error", "critical", "fatal",
                        "warning", "warn",
                    ):
                        return True
                if isinstance(child.func, ast.Name):
                    if child.func.id in ("print", "logging"):
                        return True
        return False
