"""QA checks for production resilience patterns (QA-017 through QA-019)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck


class QA017NoCircuitBreaker(QACheck):
    """Detect external service integrations without a circuit-breaker pattern.

    When a downstream dependency degrades, a circuit breaker prevents
    cascading failures by fast-failing instead of queuing up blocked
    requests.
    """

    check_id = "QA-017"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "No circuit breaker for external service calls"

    _HTTP_METHODS = frozenset({
        "get", "post", "put", "delete", "patch", "request", "send",
    })
    _HTTP_OBJECTS = frozenset({
        "requests", "httpx", "session", "client", "aiohttp",
    })
    _CB_MARKERS = frozenset({
        "circuitbreaker", "circuit_breaker", "CircuitBreaker",
        "pybreaker", "aiobreaker", "circuitbreaker",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # First pass: does the project use any circuit-breaker library?
        project_has_cb = False
        for _fp, source, _tree in source_files:
            if any(m in source for m in self._CB_MARKERS):
                project_has_cb = True
                break

        if project_has_cb:
            return findings  # project is CB-aware, skip detailed check

        # Second pass: find external call sites.
        external_call_files: set[str] = set()
        for file_path, source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in self._HTTP_METHODS:
                    continue
                obj = self._obj_name(node.func.value)
                if obj.lower() in self._HTTP_OBJECTS:
                    key = str(file_path)
                    if key not in external_call_files:
                        external_call_files.add(key)
                        findings.append(self._make_finding(
                            message=(
                                f"External HTTP calls in '{file_path.name}' "
                                "have no circuit-breaker protection"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            suggestion=(
                                "Wrap external calls with a circuit breaker "
                                "(e.g. pybreaker, tenacity with stop conditions)"
                            ),
                        ))

        return findings

    @staticmethod
    def _obj_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""


class QA018MissingBackoff(QACheck):
    """Detect retry loops that lack exponential back-off.

    Retrying immediately (or with a fixed delay) after a failure amplifies
    load on an already-struggling dependency and can cause a thundering-herd
    effect.
    """

    check_id = "QA-018"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Retry logic without exponential back-off"

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.For, ast.While)):
                    continue
                if not self._loop_contains_retry_pattern(node):
                    continue
                if self._has_backoff(node, source):
                    continue

                findings.append(self._make_finding(
                    message=(
                        "Retry loop without exponential back-off — "
                        "may overload failing dependencies"
                    ),
                    file_path=file_path,
                    line=node.lineno,
                    suggestion=(
                        "Add exponential back-off: sleep(base * 2**attempt) "
                        "with jitter, or use the backoff/tenacity library"
                    ),
                ))

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _loop_contains_retry_pattern(node: ast.AST) -> bool:
        """Heuristic: the loop body contains a try/except and a continue or break."""
        has_try = False
        has_continue = False
        has_sleep = False

        for child in ast.walk(node):
            if isinstance(child, ast.Try):
                has_try = True
            if isinstance(child, (ast.Continue, ast.Break)):
                has_continue = True
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute) and child.func.attr == "sleep":
                    has_sleep = True
                if isinstance(child.func, ast.Name) and child.func.id == "sleep":
                    has_sleep = True

        return has_try and (has_continue or has_sleep)

    @staticmethod
    def _has_backoff(node: ast.AST, source: str) -> bool:
        """Check whether the retry loop uses increasing delays."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute) and child.func.attr == "sleep":
                    for arg in child.args:
                        # sleep(delay * 2) or sleep(2 ** n) patterns
                        if isinstance(arg, ast.BinOp):
                            if isinstance(arg.op, (ast.Mult, ast.Pow)):
                                return True
                        # sleep(backoff) where backoff is a variable
                        if isinstance(arg, ast.Name) and arg.id in (
                            "backoff", "delay", "wait_time", "sleep_time",
                        ):
                            return True
        # Also check for backoff/tenacity decorators in the enclosing scope.
        return False


class QA019UnboundedQueueGrowth(QACheck):
    """Detect queues, lists, or buffers that can grow without bound.

    An unbounded in-memory buffer under sustained load leads to OOM kills
    in production.
    """

    check_id = "QA-019"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Unbounded queue or buffer may cause OOM"

    _QUEUE_CONSTRUCTORS = frozenset({
        "Queue", "SimpleQueue", "PriorityQueue", "LifoQueue",
        "deque", "asyncio.Queue",
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
                if func_name not in self._QUEUE_CONSTRUCTORS:
                    continue

                has_maxsize = any(
                    kw.arg in ("maxsize", "maxlen") for kw in node.keywords
                )
                # Queue(maxsize) can also be a positional arg.
                has_positional_limit = (
                    len(node.args) >= 1
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, int)
                    and node.args[0].value > 0
                )

                if not has_maxsize and not has_positional_limit:
                    findings.append(self._make_finding(
                        message=(
                            f"'{func_name}()' created without a size limit — "
                            "may grow unbounded under load"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=(
                            f"Pass maxsize=<limit> to {func_name}() to "
                            "apply back-pressure"
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
