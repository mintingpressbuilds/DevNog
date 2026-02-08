"""QA checks for production observability (QA-022 through QA-025)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck


class QA022MissingStructuredLogging(QACheck):
    """Detect services that use ``print()`` or basic logging instead of
    structured (JSON / key-value) logging.

    Structured logs are machine-parseable, enabling log aggregation tools
    (ELK, Datadog, CloudWatch) to index, filter and alert effectively.
    """

    check_id = "QA-022"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Using print() or basic logging instead of structured logging"

    _STRUCTURED_MARKERS = frozenset({
        "structlog", "python_json_logger", "json_log_formatter",
        "pythonjsonlogger", "loguru", "JsonFormatter",
        "JSONFormatter", "StructuredLogger",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Project-wide check: is structured logging configured anywhere?
        has_structured = any(
            any(m in source for m in self._STRUCTURED_MARKERS)
            for _, source, _ in source_files
        )
        if has_structured:
            return findings

        # Check per-file for print-based or basic logging.
        print_files: list[tuple[Path, int]] = []
        for file_path, _source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    # Ignore test files.
                    if "test" in str(file_path).lower():
                        continue
                    print_files.append((file_path, node.lineno))
                    break  # one finding per file is enough

        if len(print_files) >= 3:
            # Report once for the project (too noisy per-file).
            findings.append(self._make_finding(
                message=(
                    f"Project uses print() for output in {len(print_files)} "
                    "files — structured logging is not configured"
                ),
                file_path=print_files[0][0],
                line=print_files[0][1],
                suggestion=(
                    "Replace print() calls with a structured logging library "
                    "(e.g. structlog, python-json-logger) for production "
                    "observability"
                ),
            ))
        elif print_files:
            for fp, line in print_files:
                findings.append(self._make_finding(
                    message=f"print() used in '{fp.name}' — prefer structured logging",
                    file_path=fp,
                    line=line,
                    suggestion="Replace with logger.info(..., extra={{...}}) or structlog",
                ))

        return findings


class QA023NoRequestTracing(QACheck):
    """Detect web services without request tracing / correlation IDs.

    Without a correlation ID propagated through the call chain, diagnosing
    production issues across microservices requires painful timestamp
    alignment.
    """

    check_id = "QA-023"
    category = Category.PROD_READINESS
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "No request tracing or correlation ID support"

    _TRACING_MARKERS = frozenset({
        "opentelemetry", "jaeger", "zipkin", "datadog",
        "x-request-id", "x_request_id", "correlation_id",
        "correlationid", "trace_id", "traceid",
        "request_id", "requestid",
        "OpenTelemetry", "TracerProvider",
        "ddtrace", "newrelic",
    })
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
        has_tracing = False

        for _fp, source, _tree in source_files:
            lower = source.lower()
            if any(m in lower for m in self._WEB_MARKERS):
                is_web = True
            if any(m.lower() in lower for m in self._TRACING_MARKERS):
                has_tracing = True

        if is_web and not has_tracing:
            findings.append(self._make_finding(
                message=(
                    "Web service has no request tracing or correlation ID "
                    "support — cross-service debugging will be difficult"
                ),
                suggestion=(
                    "Integrate OpenTelemetry, or add middleware that injects "
                    "and propagates an X-Request-ID header"
                ),
            ))

        return findings


class QA024MissingMetrics(QACheck):
    """Detect services that expose no application metrics.

    Without metrics (latency histograms, error rates, queue depths),
    operators have no visibility into service health beyond binary
    up/down checks.
    """

    check_id = "QA-024"
    category = Category.PROD_READINESS
    severity = Severity.INFO
    fix_type = FixType.AI_GENERATED
    description = "No application metrics instrumentation detected"

    _METRICS_MARKERS = frozenset({
        "prometheus_client", "prometheus", "statsd", "datadog",
        "opentelemetry.metrics", "Counter(", "Histogram(",
        "Gauge(", "Summary(", "metrics",
        "REGISTRY", "start_http_server",
        "collectd", "influxdb",
    })
    _WEB_MARKERS = frozenset({
        "flask", "fastapi", "django", "starlette", "aiohttp",
        "tornado", "sanic",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_web = False
        has_metrics = False

        for _fp, source, _tree in source_files:
            lower = source.lower()
            if any(m in lower for m in self._WEB_MARKERS):
                is_web = True
            if any(m.lower() in lower for m in self._METRICS_MARKERS):
                has_metrics = True

        if is_web and not has_metrics:
            findings.append(self._make_finding(
                message=(
                    "Web service has no metrics instrumentation — operators "
                    "have no visibility beyond logs"
                ),
                suggestion=(
                    "Add prometheus_client, OpenTelemetry metrics, or StatsD "
                    "to expose latency, error rate, and throughput metrics"
                ),
            ))

        return findings


class QA025NoErrorReporting(QACheck):
    """Detect services without an external error reporting integration.

    Relying solely on logs for error visibility means issues are discovered
    late (or never).  A dedicated error tracker (Sentry, Bugsnag, Rollbar)
    provides alerting, grouping, and trend analysis.
    """

    check_id = "QA-025"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "No external error reporting integration"

    _ERROR_REPORTERS = frozenset({
        "sentry_sdk", "sentry", "bugsnag", "rollbar", "airbrake",
        "honeybadger", "raygun", "errorhandler",
        "init_sentry", "configure_sentry",
    })
    _SERVICE_MARKERS = frozenset({
        "flask", "fastapi", "django", "starlette", "celery",
        "aiohttp", "tornado", "sanic",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_service = False
        has_reporter = False

        for _fp, source, _tree in source_files:
            lower = source.lower()
            if any(m in lower for m in self._SERVICE_MARKERS):
                is_service = True
            if any(m in lower for m in self._ERROR_REPORTERS):
                has_reporter = True

        if is_service and not has_reporter:
            findings.append(self._make_finding(
                message=(
                    "Service has no external error reporting integration — "
                    "production errors may go unnoticed"
                ),
                suggestion=(
                    "Integrate Sentry (sentry_sdk.init()), Bugsnag, or "
                    "Rollbar for real-time error alerting and triage"
                ),
            ))

        return findings
