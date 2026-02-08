"""QA checks for timeout enforcement (QA-004 through QA-006)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck


class QA004HTTPClientTimeout(QACheck):
    """Detect HTTP client calls that omit the ``timeout`` parameter.

    An HTTP request without a timeout can block a thread (or event-loop)
    indefinitely, eventually exhausting the process's capacity to handle
    new work.
    """

    check_id = "QA-004"
    category = Category.PROD_READINESS
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "HTTP client call missing timeout parameter"
    required = True

    _HTTP_METHODS = frozenset({
        "get", "post", "put", "delete", "patch", "head", "options", "request",
        "send",
    })
    _HTTP_OBJECTS = frozenset({
        "requests", "httpx", "session", "client", "http", "aiohttp",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            # Skip if a default timeout is configured at module level.
            if self._has_default_timeout(source):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in self._HTTP_METHODS:
                    continue

                obj_name = self._obj_name(node.func.value)
                if obj_name.lower() not in self._HTTP_OBJECTS:
                    continue

                has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                if not has_timeout:
                    findings.append(self._make_finding(
                        message=(
                            f"HTTP call '{obj_name}.{node.func.attr}()' has no "
                            "timeout — may block indefinitely"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Add timeout=<seconds> (e.g. timeout=30)",
                    ))

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _obj_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _has_default_timeout(source: str) -> bool:
        lower = source.lower()
        return (
            "default_timeout" in lower
            or "timeout=" in lower and "session(" in lower
            or "httpx.client(" in lower and "timeout" in lower
        )


class QA005DatabaseOperationTimeout(QACheck):
    """Detect database operations that lack a query/connection timeout.

    A long-running or deadlocked query without a timeout can hold
    connections and degrade the entire service.
    """

    check_id = "QA-005"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Database operation missing timeout / statement_timeout"

    _DB_CONNECT_FUNCS = frozenset({
        "connect", "create_engine", "create_async_engine",
        "Connection", "AsyncConnection",
    })
    _TIMEOUT_KWARGS = frozenset({
        "timeout", "connect_timeout", "statement_timeout",
        "command_timeout", "pool_timeout",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = self._call_name(node)
                if func_name not in self._DB_CONNECT_FUNCS:
                    continue

                has_timeout = any(
                    kw.arg in self._TIMEOUT_KWARGS for kw in node.keywords
                )
                if not has_timeout:
                    findings.append(self._make_finding(
                        message=(
                            f"Database call '{func_name}()' has no timeout — "
                            "runaway queries may block the service"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Pass connect_timeout / statement_timeout in the "
                            "connection or engine options"
                        ),
                    ))

        return findings

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


class QA006SocketConnectionTimeout(QACheck):
    """Detect raw socket or low-level connection calls without timeouts.

    Sockets default to blocking mode with no timeout, which is dangerous
    in production if the remote side hangs.
    """

    check_id = "QA-006"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Socket / low-level connection missing timeout"

    _SOCKET_CALLS = frozenset({
        "socket", "create_connection", "connect", "connect_ex",
    })
    _SOCKET_MODULES = frozenset({
        "socket", "ssl",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            # Only inspect files that import socket / ssl.
            if not self._imports_socket(tree):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = self._call_name(node)
                if func_name not in self._SOCKET_CALLS:
                    continue

                has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                if not has_timeout:
                    # Also check positional args for create_connection
                    # which takes timeout as 3rd arg.
                    if func_name == "create_connection" and len(node.args) >= 3:
                        continue

                    findings.append(self._make_finding(
                        message=(
                            f"Socket call '{func_name}()' has no timeout — "
                            "may block indefinitely on network issues"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Pass timeout parameter or call socket.settimeout()",
                    ))

            # Also check for socket objects that never call settimeout.
            self._check_settimeout(file_path, tree, findings)

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _imports_socket(tree: ast.Module) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("socket", "ssl"):
                        return True
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in ("socket", "ssl"):
                    return True
        return False

    def _check_settimeout(
        self, file_path: Path, tree: ast.Module, findings: list[Finding]
    ) -> None:
        """Warn about ``socket.socket()`` calls in functions with no settimeout."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            creates_socket = False
            calls_settimeout = False
            socket_line = 0

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = self._call_name(child)
                    if name == "socket" or (
                        isinstance(child.func, ast.Attribute)
                        and child.func.attr == "socket"
                    ):
                        creates_socket = True
                        socket_line = child.lineno
                    if isinstance(child.func, ast.Attribute):
                        if child.func.attr in ("settimeout", "setdefaulttimeout"):
                            calls_settimeout = True

            if creates_socket and not calls_settimeout and socket_line:
                findings.append(self._make_finding(
                    message=(
                        f"Socket created in '{node.name}()' without "
                        "settimeout() — defaults to blocking forever"
                    ),
                    file_path=file_path,
                    line=socket_line,
                    suggestion="Call sock.settimeout(<seconds>) after creation",
                ))
