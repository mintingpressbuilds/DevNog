"""QA checks for production performance concerns (QA-020 through QA-021)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck


class QA020NPlusOneQueryPattern(QACheck):
    """Detect potential N+1 query patterns.

    Issuing one database query per loop iteration turns an O(1) batch into
    O(N) round-trips, which becomes a severe latency bottleneck once the
    dataset grows.
    """

    check_id = "QA-020"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Potential N+1 query pattern detected"

    _DB_QUERY_METHODS = frozenset({
        "execute", "fetchone", "fetchall", "fetch", "first",
        "get", "filter", "filter_by", "query", "select",
        "find", "find_one", "find_all",
        "get_object_or_404", "get_or_404",
    })
    _ORM_ATTRIBUTE_ACCESS = frozenset({
        "all", "first", "one", "one_or_none", "scalar",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, _source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.For, ast.AsyncFor)):
                    continue
                self._check_loop_body(node, file_path, findings)

        return findings

    def _check_loop_body(
        self,
        loop_node: ast.For | ast.AsyncFor,
        file_path: Path,
        findings: list[Finding],
    ) -> None:
        """Flag query calls inside a loop body."""
        query_calls_in_loop: list[tuple[str, int]] = []

        for child in ast.walk(loop_node):
            if child is loop_node:
                continue
            if not isinstance(child, ast.Call):
                continue

            name = self._call_attr(child)
            if name in self._DB_QUERY_METHODS or name in self._ORM_ATTRIBUTE_ACCESS:
                query_calls_in_loop.append((name, child.lineno))

        # Report first occurrence per loop to avoid noise.
        if query_calls_in_loop:
            name, line = query_calls_in_loop[0]
            findings.append(self._make_finding(
                message=(
                    f"Potential N+1 query: '{name}()' called inside a loop "
                    f"({len(query_calls_in_loop)} query call(s) in loop body)"
                ),
                file_path=file_path,
                line=line,
                suggestion=(
                    "Batch the query before the loop using prefetch_related(), "
                    "selectinload(), or a single query with an IN clause"
                ),
            ))

    @staticmethod
    def _call_attr(node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""


class QA021SyncIOInAsyncContext(QACheck):
    """Detect synchronous blocking I/O used inside async functions.

    Blocking the event loop with synchronous file, network, or sleep calls
    starves all other coroutines and degrades throughput.
    """

    check_id = "QA-021"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Synchronous blocking I/O inside async function"

    _BLOCKING_CALLS = frozenset({
        "open",
        "sleep",
        "read", "readline", "readlines",
        "write", "writelines",
        "recv", "send", "sendall", "accept",
        "connect",
        "urlopen",
        "input",
    })
    _BLOCKING_ATTR_CALLS = frozenset({
        "read_text", "read_bytes", "write_text", "write_bytes",
    })
    _SYNC_HTTP = frozenset({
        "requests",
    })
    _SYNC_HTTP_METHODS = frozenset({
        "get", "post", "put", "delete", "patch", "head", "options",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, _source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, ast.AsyncFunctionDef):
                    continue
                self._check_async_body(node, file_path, findings)

        return findings

    def _check_async_body(
        self,
        func_node: ast.AsyncFunctionDef,
        file_path: Path,
        findings: list[Finding],
    ) -> None:
        reported_lines: set[int] = set()

        for child in ast.walk(func_node):
            if not isinstance(child, ast.Call):
                continue

            # Direct blocking call: open(), sleep(), etc.
            if isinstance(child.func, ast.Name):
                if child.func.id in self._BLOCKING_CALLS:
                    # time.sleep is caught below via Attribute; skip bare
                    # "sleep" if it might be asyncio.sleep
                    if child.func.id == "sleep":
                        continue
                    if child.func.id == "open":
                        self._add_finding(
                            func_node, child, "open()", file_path,
                            findings, reported_lines,
                            suggestion="Use aiofiles.open() or run_in_executor()",
                        )

            if not isinstance(child.func, ast.Attribute):
                continue

            attr = child.func.attr
            obj_name = self._obj_name(child.func.value)

            # time.sleep() inside async
            if attr == "sleep" and obj_name == "time":
                self._add_finding(
                    func_node, child, "time.sleep()", file_path,
                    findings, reported_lines,
                    suggestion="Use await asyncio.sleep() instead",
                )

            # requests.get() etc. inside async
            if obj_name.lower() in self._SYNC_HTTP and attr in self._SYNC_HTTP_METHODS:
                self._add_finding(
                    func_node, child, f"{obj_name}.{attr}()", file_path,
                    findings, reported_lines,
                    suggestion="Use httpx.AsyncClient or aiohttp instead of requests",
                )

            # Path.read_text() etc. inside async
            if attr in self._BLOCKING_ATTR_CALLS:
                self._add_finding(
                    func_node, child, f".{attr}()", file_path,
                    findings, reported_lines,
                    suggestion=(
                        "Use aiofiles or loop.run_in_executor() for "
                        "file I/O in async context"
                    ),
                )

    def _add_finding(
        self,
        func_node: ast.AsyncFunctionDef,
        call_node: ast.Call,
        call_desc: str,
        file_path: Path,
        findings: list[Finding],
        reported_lines: set[int],
        suggestion: str = "",
    ) -> None:
        if call_node.lineno in reported_lines:
            return
        reported_lines.add(call_node.lineno)
        findings.append(self._make_finding(
            message=(
                f"Blocking call '{call_desc}' inside async function "
                f"'{func_node.name}()' — will block the event loop"
            ),
            file_path=file_path,
            line=call_node.lineno,
            suggestion=suggestion,
        ))

    @staticmethod
    def _obj_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""
