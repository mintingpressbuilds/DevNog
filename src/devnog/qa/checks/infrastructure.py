"""QA checks for production infrastructure readiness (QA-007 through QA-011)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck

# ======================================================================
# Shared helpers
# ======================================================================

_FRAMEWORK_ENTRY_NAMES = frozenset({
    "app.py", "application.py", "main.py", "server.py",
    "wsgi.py", "asgi.py", "__main__.py", "manage.py",
})


def _file_contains_any(source: str, markers: frozenset[str]) -> bool:
    lower = source.lower()
    return any(m in lower for m in markers)


# ======================================================================
# QA-007  Health-check endpoint
# ======================================================================

class QA007MissingHealthCheck(QACheck):
    """Detect web services that expose no health-check endpoint.

    Orchestrators (Kubernetes, ECS, systemd) need a lightweight endpoint to
    verify the process is alive and able to serve traffic.
    """

    check_id = "QA-007"
    category = Category.PROD_READINESS
    severity = Severity.CRITICAL
    fix_type = FixType.AI_GENERATED
    description = "No health-check endpoint detected"
    required = True

    _HEALTH_PATTERNS = frozenset({
        "/health", "/healthz", "/readyz", "/livez",
        "/ping", "/_health", "/status",
        "health_check", "healthcheck", "liveness",
    })
    _WEB_MARKERS = frozenset({
        "flask", "fastapi", "django", "starlette", "aiohttp",
        "tornado", "sanic", "falcon", "bottle", "quart",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_web_project = False
        has_health_endpoint = False

        for file_path, source, tree in source_files:
            lower = source.lower()

            if any(m in lower for m in self._WEB_MARKERS):
                is_web_project = True

            if any(p in lower for p in self._HEALTH_PATTERNS):
                has_health_endpoint = True

        if is_web_project and not has_health_endpoint:
            findings.append(self._make_finding(
                message=(
                    "Web service has no health-check endpoint — orchestrators "
                    "cannot determine service health"
                ),
                suggestion=(
                    "Add a /health or /healthz endpoint that returns 200 OK "
                    "when the service is ready to handle traffic"
                ),
            ))

        return findings


# ======================================================================
# QA-008  Graceful shutdown
# ======================================================================

class QA008NoGracefulShutdown(QACheck):
    """Detect services that lack graceful shutdown handling.

    Without a graceful shutdown, in-flight requests are dropped and
    resources (DB connections, file handles) may leak on termination.
    """

    check_id = "QA-008"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "No graceful shutdown handler detected"

    _SHUTDOWN_MARKERS = frozenset({
        "sigterm", "sigint", "signal.signal",
        "atexit", "on_shutdown", "shutdown_event",
        "add_event_handler", "lifespan",
        "graceful", "cleanup",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        has_shutdown = False
        is_service = False

        for file_path, source, tree in source_files:
            lower = source.lower()
            if file_path.name in _FRAMEWORK_ENTRY_NAMES:
                is_service = True
            if any(m in lower for m in ("flask", "fastapi", "django", "uvicorn", "gunicorn")):
                is_service = True
            if any(m in lower for m in self._SHUTDOWN_MARKERS):
                has_shutdown = True

        if is_service and not has_shutdown:
            findings.append(self._make_finding(
                message=(
                    "Service has no graceful shutdown handler — in-flight "
                    "work will be lost on SIGTERM"
                ),
                suggestion=(
                    "Register a SIGTERM/SIGINT handler or use the "
                    "framework's shutdown hook (e.g. FastAPI lifespan, "
                    "Flask teardown_appcontext)."
                ),
            ))

        return findings


# ======================================================================
# QA-009  Liveness / Readiness probes
# ======================================================================

class QA009MissingReadinessProbe(QACheck):
    """Detect services missing readiness vs. liveness distinction.

    A liveness probe confirms the process hasn't deadlocked.  A readiness
    probe confirms it can actually serve traffic (DB connected, caches warm,
    etc.).  Combining both into one endpoint causes false restarts.
    """

    check_id = "QA-009"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Missing separate readiness/liveness probes"

    _READINESS = frozenset({"/readyz", "/ready", "readiness"})
    _LIVENESS = frozenset({"/livez", "/alive", "/ping", "liveness"})
    _HEALTH_GENERIC = frozenset({"/health", "/healthz", "health_check"})
    _WEB_MARKERS = frozenset({
        "flask", "fastapi", "django", "starlette", "aiohttp",
        "tornado", "sanic", "falcon",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_web = False
        has_readiness = False
        has_liveness = False
        has_generic = False

        for _fp, source, _tree in source_files:
            lower = source.lower()
            if any(m in lower for m in self._WEB_MARKERS):
                is_web = True
            if any(m in lower for m in self._READINESS):
                has_readiness = True
            if any(m in lower for m in self._LIVENESS):
                has_liveness = True
            if any(m in lower for m in self._HEALTH_GENERIC):
                has_generic = True

        if is_web and has_generic and not (has_readiness and has_liveness):
            findings.append(self._make_finding(
                message=(
                    "Service has a generic /health endpoint but no separate "
                    "readiness and liveness probes"
                ),
                suggestion=(
                    "Split into /readyz (checks dependencies) and /livez "
                    "(lightweight heartbeat) for safer rolling deployments."
                ),
            ))

        return findings


# ======================================================================
# QA-010  Hardcoded host / port
# ======================================================================

class QA010HardcodedHostPort(QACheck):
    """Detect hardcoded host addresses or port numbers in service startup.

    Hardcoded values prevent proper configuration per environment (dev,
    staging, prod) and break container orchestration.
    """

    check_id = "QA-010"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Hardcoded host or port in service binding"

    _BIND_FUNCS = frozenset({
        "run", "serve", "listen", "bind", "uvicorn.run",
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
                if func_name not in self._BIND_FUNCS:
                    continue

                for kw in node.keywords:
                    if kw.arg in ("host", "port"):
                        if isinstance(kw.value, ast.Constant):
                            val = kw.value.value
                            # Allow 0.0.0.0 (common in containers) and 0
                            if val in ("0.0.0.0", 0):
                                continue
                            findings.append(self._make_finding(
                                message=(
                                    f"Hardcoded {kw.arg}={val!r} in "
                                    f"'{func_name}()' call"
                                ),
                                file_path=file_path,
                                line=node.lineno,
                                suggestion=(
                                    f"Read {kw.arg} from environment variable "
                                    f"or configuration file"
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


# ======================================================================
# QA-011  Process signal handlers
# ======================================================================

class QA011MissingSignalHandlers(QACheck):
    """Detect long-running services without SIGTERM / SIGINT handlers.

    Container runtimes and process managers send SIGTERM before SIGKILL.
    Without a handler, cleanup code never runs.
    """

    check_id = "QA-011"
    category = Category.PROD_READINESS
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "No process signal handlers registered"

    _SIGNAL_MARKERS = frozenset({
        "signal.signal", "signal.SIGTERM", "signal.SIGINT",
        "loop.add_signal_handler",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_service = False
        has_signal_handler = False

        for file_path, source, tree in source_files:
            if file_path.name in _FRAMEWORK_ENTRY_NAMES:
                is_service = True

            if any(m in source for m in self._SIGNAL_MARKERS):
                has_signal_handler = True

            # Also check for signal imports used in code.
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "signal":
                            # Having the import is not enough; check usage.
                            if "signal.signal" in source:
                                has_signal_handler = True

        if is_service and not has_signal_handler:
            findings.append(self._make_finding(
                message=(
                    "Service does not register SIGTERM/SIGINT handlers — "
                    "cleanup will not run on graceful termination"
                ),
                suggestion=(
                    "Register signal.signal(signal.SIGTERM, handler) or use "
                    "asyncio loop.add_signal_handler() to trigger cleanup."
                ),
            ))

        return findings
