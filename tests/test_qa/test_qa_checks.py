"""Tests for QA Gate checks QA-001 through QA-025."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from devnog.qa.checks.error_handling import (
    QA001UnhandledEntryPointExceptions,
    QA002MissingRetryOnExternalCalls,
    QA003CatchAllWithoutReraise,
)
from devnog.qa.checks.timeouts import (
    QA004HTTPClientTimeout,
    QA005DatabaseOperationTimeout,
    QA006SocketConnectionTimeout,
)
from devnog.qa.checks.infrastructure import (
    QA007MissingHealthCheck,
    QA008NoGracefulShutdown,
    QA009MissingReadinessProbe,
    QA010HardcodedHostPort,
    QA011MissingSignalHandlers,
)
from devnog.qa.checks.data_safety import (
    QA012SQLWithoutParameterization,
    QA013MissingTransactionHandling,
)
from devnog.qa.checks.config import (
    QA014HardcodedSecrets,
    QA015DebugModeEnabled,
    QA016MissingEnvValidation,
)
from devnog.qa.checks.resilience import (
    QA017NoCircuitBreaker,
    QA018MissingBackoff,
    QA019UnboundedQueueGrowth,
)
from devnog.qa.checks.performance import (
    QA020NPlusOneQueryPattern,
    QA021SyncIOInAsyncContext,
)
from devnog.qa.checks.observability import (
    QA022MissingStructuredLogging,
    QA023NoRequestTracing,
    QA024MissingMetrics,
    QA025NoErrorReporting,
)
from devnog.core.models import Category, Finding, Severity


FAKE_PROJECT = Path("/fake/project")


def _make_source_files(
    source: str,
    filename: str = "module.py",
) -> list[tuple[Path, str, ast.Module]]:
    """Parse *source* and return source_files list suitable for QA checks."""
    src = textwrap.dedent(source)
    tree = ast.parse(src, filename=filename)
    file_path = FAKE_PROJECT / filename
    return [(file_path, src, tree)]


def _make_multi_source_files(
    files: dict[str, str],
) -> list[tuple[Path, str, ast.Module]]:
    """Build source_files from a dict of {filename: source}."""
    result: list[tuple[Path, str, ast.Module]] = []
    for filename, source in files.items():
        src = textwrap.dedent(source)
        tree = ast.parse(src, filename=filename)
        file_path = FAKE_PROJECT / filename
        result.append((file_path, src, tree))
    return result


# ---------------------------------------------------------------------------
# QA-001: Entry point lacks top-level exception handling
# ---------------------------------------------------------------------------
class TestQA001UnhandledEntryPointExceptions:
    def test_detects_unhandled_entry_point(self):
        """An entry-point file without try/except should trigger QA-001."""
        source = """\
        import sys

        def main():
            print("hello")

        if __name__ == "__main__":
            main()
        """
        check = QA001UnhandledEntryPointExceptions()
        findings = check.run(FAKE_PROJECT, _make_source_files(source, "main.py"))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_clean_entry_point_with_try_except(self):
        """An entry-point with a try/except in __main__ guard is clean."""
        source = """\
        import sys

        def main():
            print("hello")

        if __name__ == "__main__":
            try:
                main()
            except Exception as e:
                print(e)
                sys.exit(1)
        """
        check = QA001UnhandledEntryPointExceptions()
        findings = check.run(FAKE_PROJECT, _make_source_files(source, "app.py"))
        assert len(findings) == 0

    def test_clean_entry_point_with_module_level_try(self):
        """A module-level try block in entry-point is acceptable."""
        source = """\
        try:
            import sys
            def main():
                print("hello")
            main()
        except Exception:
            pass
        """
        check = QA001UnhandledEntryPointExceptions()
        findings = check.run(FAKE_PROJECT, _make_source_files(source, "app.py"))
        assert len(findings) == 0

    def test_clean_entry_point_with_sys_excepthook(self):
        """Entry-point using sys.excepthook is acceptable."""
        source = """\
        import sys

        def handler(exc_type, exc_val, exc_tb):
            pass

        sys.excepthook = handler

        def main():
            print("hello")
        """
        check = QA001UnhandledEntryPointExceptions()
        findings = check.run(FAKE_PROJECT, _make_source_files(source, "main.py"))
        assert len(findings) == 0

    def test_non_entry_point_ignored(self):
        """Non-entry-point files are not checked."""
        source = """\
        def foo():
            print("hello")
        """
        check = QA001UnhandledEntryPointExceptions()
        findings = check.run(FAKE_PROJECT, _make_source_files(source, "utils.py"))
        assert len(findings) == 0

    def test_required_flag(self):
        """QA-001 should be marked as required."""
        check = QA001UnhandledEntryPointExceptions()
        assert check.required is True


# ---------------------------------------------------------------------------
# QA-002: External service call lacks retry logic
# ---------------------------------------------------------------------------
class TestQA002MissingRetryOnExternalCalls:
    def test_detects_http_call_without_retry(self):
        """An HTTP call without retry markers should trigger QA-002."""
        source = """\
        import requests

        def fetch_data():
            response = requests.get("https://api.example.com/data")
            return response.json()
        """
        check = QA002MissingRetryOnExternalCalls()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-002"
        assert findings[0].severity == Severity.WARNING

    def test_clean_with_retry_import(self):
        """File importing a retry library should not trigger QA-002."""
        source = """\
        import requests
        from tenacity import retry

        @retry
        def fetch_data():
            response = requests.get("https://api.example.com/data")
            return response.json()
        """
        check = QA002MissingRetryOnExternalCalls()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_retry_decorator(self):
        """Function decorated with retry should not trigger QA-002."""
        source = """\
        import requests
        from backoff import on_exception

        @on_exception(backoff.expo, Exception)
        def fetch_data():
            response = requests.get("https://api.example.com/data")
            return response.json()
        """
        check = QA002MissingRetryOnExternalCalls()
        # The file contains "backoff" marker, so it should be skipped.
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_detects_httpx_without_retry(self):
        """httpx calls without retry should trigger QA-002."""
        source = """\
        import httpx

        def fetch():
            httpx.post("https://api.example.com/data", json={})
        """
        check = QA002MissingRetryOnExternalCalls()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_non_http_call_ignored(self):
        """Regular method calls should not trigger QA-002."""
        source = """\
        class MyObj:
            def get(self):
                return 42

        obj = MyObj()
        obj.get()
        """
        check = QA002MissingRetryOnExternalCalls()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-003: Catch-all exception handler swallows errors
# ---------------------------------------------------------------------------
class TestQA003CatchAllWithoutReraise:
    def test_detects_swallowed_exception(self):
        """A bare except that does nothing should trigger QA-003."""
        source = """\
        def risky():
            try:
                do_something()
            except Exception:
                pass
        """
        check = QA003CatchAllWithoutReraise()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-003"

    def test_detects_bare_except_swallow(self):
        """A bare 'except:' block that swallows is flagged."""
        source = """\
        try:
            something()
        except:
            pass
        """
        check = QA003CatchAllWithoutReraise()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_with_reraise(self):
        """Broad except that re-raises should not trigger QA-003."""
        source = """\
        def risky():
            try:
                do_something()
            except Exception as e:
                cleanup()
                raise
        """
        check = QA003CatchAllWithoutReraise()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_logging(self):
        """Broad except that logs the error should not trigger QA-003."""
        source = """\
        import logging
        logger = logging.getLogger(__name__)

        def risky():
            try:
                do_something()
            except Exception as e:
                logger.exception("Failed")
        """
        check = QA003CatchAllWithoutReraise()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_specific_exception_not_flagged(self):
        """Catching a specific exception (not Exception/BaseException) is OK."""
        source = """\
        def risky():
            try:
                int("bad")
            except ValueError:
                pass
        """
        check = QA003CatchAllWithoutReraise()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_error_call(self):
        """Broad except that calls logger.error() should not trigger."""
        source = """\
        def risky():
            try:
                do_something()
            except Exception as e:
                logger.error("Something went wrong: %s", e)
        """
        check = QA003CatchAllWithoutReraise()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-004: HTTP client call missing timeout parameter
# ---------------------------------------------------------------------------
class TestQA004HTTPClientTimeout:
    def test_detects_missing_timeout(self):
        """HTTP call without timeout should trigger QA-004."""
        source = """\
        import requests

        def fetch():
            response = requests.get("https://api.example.com")
            return response.json()
        """
        check = QA004HTTPClientTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-004"
        assert findings[0].severity == Severity.CRITICAL

    def test_clean_with_timeout(self):
        """HTTP call with explicit timeout is clean."""
        source = """\
        import requests

        def fetch():
            response = requests.get("https://api.example.com", timeout=30)
            return response.json()
        """
        check = QA004HTTPClientTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_default_timeout(self):
        """File with a session-level default timeout is clean."""
        source = """\
        import requests

        session = requests.Session(timeout=30)

        def fetch():
            response = session.get("https://api.example.com")
            return response.json()
        """
        check = QA004HTTPClientTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_detects_post_without_timeout(self):
        """POST call without timeout should trigger QA-004."""
        source = """\
        import requests
        requests.post("https://api.example.com/data", json={"key": "value"})
        """
        check = QA004HTTPClientTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_required_flag(self):
        """QA-004 should be marked as required."""
        check = QA004HTTPClientTimeout()
        assert check.required is True


# ---------------------------------------------------------------------------
# QA-005: Database operation missing timeout
# ---------------------------------------------------------------------------
class TestQA005DatabaseOperationTimeout:
    def test_detects_db_connect_without_timeout(self):
        """Database connect() without timeout should trigger QA-005."""
        source = """\
        import psycopg2

        conn = psycopg2.connect("dbname=mydb user=admin")
        """
        check = QA005DatabaseOperationTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-005"

    def test_clean_with_timeout_kwarg(self):
        """Database connect() with connect_timeout is clean."""
        source = """\
        import psycopg2

        conn = psycopg2.connect("dbname=mydb", connect_timeout=10)
        """
        check = QA005DatabaseOperationTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_detects_create_engine_without_timeout(self):
        """SQLAlchemy create_engine() without timeout should trigger."""
        source = """\
        from sqlalchemy import create_engine

        engine = create_engine("postgresql://user:pass@localhost/db")
        """
        check = QA005DatabaseOperationTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_create_engine_with_pool_timeout(self):
        """SQLAlchemy create_engine() with pool_timeout is clean."""
        source = """\
        from sqlalchemy import create_engine

        engine = create_engine("postgresql://localhost/db", pool_timeout=30)
        """
        check = QA005DatabaseOperationTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-006: Socket / low-level connection missing timeout
# ---------------------------------------------------------------------------
class TestQA006SocketConnectionTimeout:
    def test_detects_socket_without_timeout(self):
        """socket.create_connection() without timeout should trigger QA-006."""
        source = """\
        import socket

        def connect():
            sock = socket.create_connection(("example.com", 80))
            return sock
        """
        check = QA006SocketConnectionTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-006"

    def test_clean_with_timeout_kwarg(self):
        """create_connection with timeout keyword is clean."""
        source = """\
        import socket

        def connect():
            sock = socket.create_connection(("example.com", 80), timeout=10)
            return sock
        """
        check = QA006SocketConnectionTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        # The function still creates a socket without settimeout,
        # but create_connection with timeout= is acceptable for the
        # create_connection check itself.
        create_conn_findings = [
            f for f in findings if "create_connection" in f.message
        ]
        assert len(create_conn_findings) == 0

    def test_clean_with_positional_timeout(self):
        """create_connection with 3+ positional args (including timeout) is clean.

        The check looks for ``len(node.args) >= 3`` because
        ``socket.create_connection(address, timeout, source_address)``
        takes timeout as the 2nd arg but the heuristic uses >= 3.
        """
        source = """\
        import socket

        def connect():
            sock = socket.create_connection(("example.com", 80), 10, ("0.0.0.0", 0))
            return sock
        """
        check = QA006SocketConnectionTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        create_conn_findings = [
            f for f in findings if "create_connection" in f.message
        ]
        assert len(create_conn_findings) == 0

    def test_detects_socket_without_settimeout(self):
        """socket.socket() in a function without settimeout should warn."""
        source = """\
        import socket

        def make_conn():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("example.com", 80))
            return s
        """
        check = QA006SocketConnectionTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        settimeout_findings = [f for f in findings if "settimeout" in f.message]
        assert len(settimeout_findings) >= 1

    def test_clean_with_settimeout(self):
        """socket.socket() followed by settimeout() is clean."""
        source = """\
        import socket

        def make_conn():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("example.com", 80))
            return s
        """
        check = QA006SocketConnectionTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        settimeout_findings = [f for f in findings if "settimeout" in f.message]
        assert len(settimeout_findings) == 0

    def test_no_socket_import_ignored(self):
        """Files without socket import are not checked."""
        source = """\
        def connect():
            obj.connect(("example.com", 80))
        """
        check = QA006SocketConnectionTimeout()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-007: No health-check endpoint detected
# ---------------------------------------------------------------------------
class TestQA007MissingHealthCheck:
    def test_detects_web_service_without_health(self):
        """A Flask app without a health endpoint should trigger QA-007."""
        source = """\
        from flask import Flask

        app = Flask(__name__)

        @app.route("/")
        def index():
            return "Hello"
        """
        check = QA007MissingHealthCheck()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-007"
        assert findings[0].severity == Severity.CRITICAL

    def test_clean_with_health_endpoint(self):
        """A Flask app with /health endpoint is clean."""
        source = """\
        from flask import Flask

        app = Flask(__name__)

        @app.route("/health")
        def health():
            return "OK", 200
        """
        check = QA007MissingHealthCheck()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_healthz(self):
        """A FastAPI app with /healthz is clean."""
        source = """\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/healthz")
        def healthz():
            return {"status": "ok"}
        """
        check = QA007MissingHealthCheck()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_web_project_ignored(self):
        """A non-web project should not trigger QA-007."""
        source = """\
        def calculate():
            return 42
        """
        check = QA007MissingHealthCheck()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_required_flag(self):
        """QA-007 should be marked as required."""
        check = QA007MissingHealthCheck()
        assert check.required is True


# ---------------------------------------------------------------------------
# QA-008: No graceful shutdown handler detected
# ---------------------------------------------------------------------------
class TestQA008NoGracefulShutdown:
    def test_detects_service_without_shutdown(self):
        """A Flask service without shutdown handling should trigger QA-008."""
        source = """\
        from flask import Flask

        app = Flask(__name__)

        @app.route("/")
        def index():
            return "Hello"
        """
        check = QA008NoGracefulShutdown()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "app.py")
        )
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-008"

    def test_clean_with_atexit(self):
        """A service registering atexit is clean."""
        source = """\
        import atexit
        from flask import Flask

        app = Flask(__name__)

        def cleanup():
            pass

        atexit.register(cleanup)
        """
        check = QA008NoGracefulShutdown()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "app.py")
        )
        assert len(findings) == 0

    def test_clean_with_signal_handler(self):
        """A service with SIGTERM handler is clean."""
        source = """\
        import signal
        from flask import Flask

        app = Flask(__name__)

        def shutdown_handler(signum, frame):
            pass

        signal.signal(signal.SIGTERM, shutdown_handler)
        """
        check = QA008NoGracefulShutdown()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "app.py")
        )
        assert len(findings) == 0

    def test_clean_with_lifespan(self):
        """A FastAPI service using lifespan is clean."""
        source = """\
        from fastapi import FastAPI

        async def lifespan(app):
            yield

        app = FastAPI(lifespan=lifespan)
        """
        check = QA008NoGracefulShutdown()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "app.py")
        )
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-009: Missing separate readiness/liveness probes
# ---------------------------------------------------------------------------
class TestQA009MissingReadinessProbe:
    def test_detects_generic_health_only(self):
        """A web service with only /health (no readyz/livez) should trigger."""
        source = """\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/health")
        def health():
            return {"status": "ok"}
        """
        check = QA009MissingReadinessProbe()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-009"

    def test_clean_with_both_probes(self):
        """A web service with /readyz and /livez is clean."""
        source = """\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/health")
        def health():
            return {"status": "ok"}

        @app.get("/readyz")
        def readyz():
            return {"ready": True}

        @app.get("/livez")
        def livez():
            return {"alive": True}
        """
        check = QA009MissingReadinessProbe()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_web_project_ignored(self):
        """Non-web projects are not checked."""
        source = """\
        def health_check():
            return True
        """
        check = QA009MissingReadinessProbe()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-010: Hardcoded host or port in service binding
# ---------------------------------------------------------------------------
class TestQA010HardcodedHostPort:
    def test_detects_hardcoded_port(self):
        """Hardcoded port in run() should trigger QA-010."""
        source = """\
        from flask import Flask

        app = Flask(__name__)
        app.run(host="0.0.0.0", port=8080)
        """
        check = QA010HardcodedHostPort()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-010"
        assert "port" in findings[0].message

    def test_detects_hardcoded_host(self):
        """Hardcoded host (not 0.0.0.0) in run() should trigger QA-010."""
        source = """\
        app.run(host="127.0.0.1", port=0)
        """
        check = QA010HardcodedHostPort()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert "host" in findings[0].message

    def test_clean_with_0000(self):
        """0.0.0.0 is allowed as it is the standard container binding."""
        source = """\
        app.run(host="0.0.0.0", port=0)
        """
        check = QA010HardcodedHostPort()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_env_var(self):
        """Using a variable (not constant) for port is clean."""
        source = """\
        import os
        port = int(os.environ.get("PORT", 8080))
        app.run(host="0.0.0.0", port=port)
        """
        check = QA010HardcodedHostPort()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_bind_function_ignored(self):
        """Regular function calls are not inspected."""
        source = """\
        def process(host="localhost", port=8080):
            pass
        process(host="localhost", port=8080)
        """
        check = QA010HardcodedHostPort()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-011: No process signal handlers registered
# ---------------------------------------------------------------------------
class TestQA011MissingSignalHandlers:
    def test_detects_service_without_signal_handlers(self):
        """A service entry-point without signal handlers should trigger."""
        source = """\
        def main():
            while True:
                process()
        """
        check = QA011MissingSignalHandlers()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "server.py")
        )
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-011"
        assert findings[0].severity == Severity.INFO

    def test_clean_with_signal_handler(self):
        """A service with signal.signal(signal.SIGTERM, ...) is clean."""
        source = """\
        import signal

        def handler(signum, frame):
            pass

        signal.signal(signal.SIGTERM, handler)

        def main():
            while True:
                process()
        """
        check = QA011MissingSignalHandlers()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "server.py")
        )
        assert len(findings) == 0

    def test_non_service_file_ignored(self):
        """Non-service files should not trigger QA-011."""
        source = """\
        def helper():
            return 42
        """
        check = QA011MissingSignalHandlers()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "utils.py")
        )
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-012: SQL query uses string formatting
# ---------------------------------------------------------------------------
class TestQA012SQLWithoutParameterization:
    def test_detects_fstring_sql(self):
        """SQL built with f-string should trigger QA-012."""
        source = """\
        def get_user(user_id):
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
        """
        check = QA012SQLWithoutParameterization()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-012"
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_percent_format_sql(self):
        """SQL built with % formatting should trigger QA-012."""
        source = """\
        def get_user(user_id):
            query = "SELECT * FROM users WHERE id = %s" % user_id
            cursor.execute(query)
        """
        check = QA012SQLWithoutParameterization()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_detects_format_method_sql(self):
        """SQL built with .format() should trigger QA-012."""
        source = """\
        def get_user(user_id):
            query = "SELECT * FROM users WHERE id = {}".format(user_id)
            cursor.execute(query)
        """
        check = QA012SQLWithoutParameterization()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_detects_concatenation_sql(self):
        """SQL built with string concatenation should trigger QA-012."""
        source = """\
        def get_user(user_id):
            query = "SELECT * FROM users WHERE id = " + user_id
            cursor.execute(query)
        """
        check = QA012SQLWithoutParameterization()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_parameterized_query(self):
        """Parameterized queries should not trigger QA-012."""
        source = """\
        def get_user(user_id):
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        """
        check = QA012SQLWithoutParameterization()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_sql_fstring_ignored(self):
        """F-strings that are not SQL should not trigger QA-012."""
        source = """\
        def greet(name):
            return f"Hello, {name}!"
        """
        check = QA012SQLWithoutParameterization()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_required_flag(self):
        """QA-012 should be marked as required."""
        check = QA012SQLWithoutParameterization()
        assert check.required is True


# ---------------------------------------------------------------------------
# QA-013: Database writes without explicit transaction handling
# ---------------------------------------------------------------------------
class TestQA013MissingTransactionHandling:
    def test_detects_writes_without_transaction(self):
        """DB writes in a function without transaction markers should trigger."""
        source = """\
        def save_user(user):
            session.add(user)
        """
        check = QA013MissingTransactionHandling()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-013"

    def test_clean_with_commit(self):
        """DB writes with commit() in the same function are clean."""
        source = """\
        def save_user(user):
            session.add(user)
            session.commit()
        """
        check = QA013MissingTransactionHandling()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_context_manager(self):
        """DB writes inside a transaction context manager are clean."""
        source = """\
        def save_user(user):
            with session.begin():
                session.add(user)
        """
        check = QA013MissingTransactionHandling()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_atomic_decorator(self):
        """DB writes in a function decorated with @atomic are clean."""
        source = """\
        @atomic
        def save_user(user):
            session.add(user)
        """
        check = QA013MissingTransactionHandling()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_no_writes_no_finding(self):
        """A function with no DB writes should not trigger."""
        source = """\
        def get_user(user_id):
            return session.query(User).filter_by(id=user_id).first()
        """
        check = QA013MissingTransactionHandling()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        # "query" and "first" are in the DB query methods but the check
        # specifically looks for _WRITE_METHODS. "first" is not in
        # _WRITE_METHODS for QA-013.
        # Actually "first" is NOT in _WRITE_METHODS. The check only
        # looks at execute, executemany, etc.
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-014: Hardcoded secret or credential in source code
# ---------------------------------------------------------------------------
class TestQA014HardcodedSecrets:
    def test_detects_hardcoded_password(self):
        """A variable named 'password' with a hardcoded string triggers."""
        source = """\
        password = "supersecret123"
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-014"
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_hardcoded_api_key(self):
        """A variable named 'api_key' with a hardcoded string triggers."""
        source = """\
        api_key = "ak_live_12345abcdef"
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_detects_annotated_assignment(self):
        """Annotated assignment to secret variable should trigger."""
        source = """\
        jwt_secret: str = "my-jwt-secret-value"
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_with_env_lookup(self):
        """Secret from os.environ should not trigger QA-014."""
        source = """\
        import os
        password = os.environ["PASSWORD"]
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_getenv(self):
        """Secret from os.getenv() should not trigger QA-014."""
        source = """\
        import os
        api_key = os.getenv("API_KEY")
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_placeholder_value(self):
        """A safe placeholder value should not trigger QA-014."""
        source = """\
        password = "changeme"
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_none_value(self):
        """A None value should not trigger QA-014."""
        source = """\
        password = None
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_test_file_ignored(self):
        """Test files should be skipped."""
        source = """\
        password = "test-secret-for-unit-test"
        """
        check = QA014HardcodedSecrets()
        findings = check.run(
            FAKE_PROJECT,
            _make_source_files(source, "test_auth.py"),
        )
        assert len(findings) == 0

    def test_required_flag(self):
        """QA-014 should be marked as required."""
        check = QA014HardcodedSecrets()
        assert check.required is True

    def test_non_secret_variable_ignored(self):
        """Normal variables should not trigger."""
        source = """\
        username = "admin"
        host = "localhost"
        """
        check = QA014HardcodedSecrets()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-015: Debug mode appears enabled in production config
# ---------------------------------------------------------------------------
class TestQA015DebugModeEnabled:
    def test_detects_debug_true(self):
        """DEBUG = True should trigger QA-015."""
        source = """\
        DEBUG = True
        """
        check = QA015DebugModeEnabled()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "settings.py")
        )
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-015"
        assert findings[0].severity == Severity.CRITICAL

    def test_clean_debug_false(self):
        """DEBUG = False should not trigger QA-015."""
        source = """\
        DEBUG = False
        """
        check = QA015DebugModeEnabled()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "settings.py")
        )
        assert len(findings) == 0

    def test_clean_debug_from_env(self):
        """DEBUG read from env should not trigger QA-015."""
        source = """\
        import os
        DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
        """
        check = QA015DebugModeEnabled()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "settings.py")
        )
        assert len(findings) == 0

    def test_dev_config_file_ignored(self):
        """Files with 'dev' in the name are skipped."""
        source = """\
        DEBUG = True
        """
        check = QA015DebugModeEnabled()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "dev_settings.py")
        )
        assert len(findings) == 0

    def test_test_config_file_ignored(self):
        """Files with 'test' in the name are skipped."""
        source = """\
        DEBUG = True
        """
        check = QA015DebugModeEnabled()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "test_settings.py")
        )
        assert len(findings) == 0

    def test_required_flag(self):
        """QA-015 should be marked as required."""
        check = QA015DebugModeEnabled()
        assert check.required is True


# ---------------------------------------------------------------------------
# QA-016: Environment variable read without validation
# ---------------------------------------------------------------------------
class TestQA016MissingEnvValidation:
    def test_detects_getenv_without_default(self):
        """os.getenv() without default should trigger QA-016."""
        source = """\
        import os
        db_host = os.getenv("DB_HOST")
        """
        check = QA016MissingEnvValidation()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-016"

    def test_detects_environ_get_without_default(self):
        """os.environ.get() without default should trigger QA-016."""
        source = """\
        import os
        db_host = os.environ.get("DB_HOST")
        """
        check = QA016MissingEnvValidation()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_with_default(self):
        """os.getenv() with a default value is clean."""
        source = """\
        import os
        db_host = os.getenv("DB_HOST", "localhost")
        """
        check = QA016MissingEnvValidation()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_environ_subscript(self):
        """os.environ['VAR'] raises KeyError, which is validation."""
        source = """\
        import os
        db_host = os.environ["DB_HOST"]
        """
        check = QA016MissingEnvValidation()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_assert_validation(self):
        """getenv followed by assert on the same line is clean."""
        source = """\
        import os
        assert os.getenv("DB_HOST")
        """
        check = QA016MissingEnvValidation()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-017: No circuit breaker for external service calls
# ---------------------------------------------------------------------------
class TestQA017NoCircuitBreaker:
    def test_detects_http_without_circuit_breaker(self):
        """HTTP calls without circuit-breaker markers should trigger QA-017."""
        source = """\
        import requests

        def fetch():
            return requests.get("https://api.example.com")
        """
        check = QA017NoCircuitBreaker()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-017"

    def test_clean_with_circuit_breaker_import(self):
        """Project using pybreaker should not trigger QA-017."""
        source = """\
        import requests
        import pybreaker

        breaker = pybreaker.CircuitBreaker()

        @breaker
        def fetch():
            return requests.get("https://api.example.com")
        """
        check = QA017NoCircuitBreaker()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_no_http_calls_no_finding(self):
        """Code without HTTP calls should not trigger."""
        source = """\
        def calculate():
            return 42
        """
        check = QA017NoCircuitBreaker()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-018: Retry logic without exponential back-off
# ---------------------------------------------------------------------------
class TestQA018MissingBackoff:
    def test_detects_retry_loop_without_backoff(self):
        """A retry loop with fixed sleep should trigger QA-018."""
        source = """\
        import time

        def fetch_with_retry():
            for attempt in range(3):
                try:
                    return do_request()
                except Exception:
                    time.sleep(1)
                    continue
        """
        check = QA018MissingBackoff()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-018"

    def test_clean_with_exponential_backoff(self):
        """A retry loop using exponential back-off is clean."""
        source = """\
        import time

        def fetch_with_retry():
            for attempt in range(3):
                try:
                    return do_request()
                except Exception:
                    time.sleep(1 * 2 ** attempt)
                    continue
        """
        check = QA018MissingBackoff()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_backoff_variable(self):
        """A retry loop using a named backoff variable is clean."""
        source = """\
        import time

        def fetch_with_retry():
            backoff = 1
            for attempt in range(3):
                try:
                    return do_request()
                except Exception:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
        """
        check = QA018MissingBackoff()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_no_retry_loop_ignored(self):
        """A regular loop without retry pattern should not trigger."""
        source = """\
        for i in range(10):
            process(i)
        """
        check = QA018MissingBackoff()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-019: Unbounded queue or buffer may cause OOM
# ---------------------------------------------------------------------------
class TestQA019UnboundedQueueGrowth:
    def test_detects_unbounded_queue(self):
        """Queue() without maxsize should trigger QA-019."""
        source = """\
        from queue import Queue

        q = Queue()
        """
        check = QA019UnboundedQueueGrowth()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-019"

    def test_clean_with_maxsize_kwarg(self):
        """Queue(maxsize=100) is clean."""
        source = """\
        from queue import Queue

        q = Queue(maxsize=100)
        """
        check = QA019UnboundedQueueGrowth()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_positional_maxsize(self):
        """Queue(100) is clean (positional maxsize)."""
        source = """\
        from queue import Queue

        q = Queue(100)
        """
        check = QA019UnboundedQueueGrowth()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_detects_unbounded_deque(self):
        """deque() without maxlen should trigger QA-019."""
        source = """\
        from collections import deque

        d = deque()
        """
        check = QA019UnboundedQueueGrowth()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_deque_with_maxlen(self):
        """deque(maxlen=1000) is clean."""
        source = """\
        from collections import deque

        d = deque(maxlen=1000)
        """
        check = QA019UnboundedQueueGrowth()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_detects_unbounded_simple_queue(self):
        """SimpleQueue() should trigger (it has no maxsize)."""
        source = """\
        from queue import SimpleQueue

        q = SimpleQueue()
        """
        check = QA019UnboundedQueueGrowth()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# QA-020: Potential N+1 query pattern detected
# ---------------------------------------------------------------------------
class TestQA020NPlusOneQueryPattern:
    def test_detects_query_in_loop(self):
        """A database query inside a loop should trigger QA-020."""
        source = """\
        def process_users(user_ids):
            for uid in user_ids:
                user = db.session.query(User).filter_by(id=uid).first()
                print(user.name)
        """
        check = QA020NPlusOneQueryPattern()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-020"

    def test_detects_execute_in_loop(self):
        """cursor.execute() inside a loop should trigger."""
        source = """\
        def update_prices(items):
            for item in items:
                cursor.execute("UPDATE products SET price = %s WHERE id = %s", (item.price, item.id))
        """
        check = QA020NPlusOneQueryPattern()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1

    def test_clean_batch_query(self):
        """A query before the loop (batch) should not trigger."""
        source = """\
        def process_users(user_ids):
            users = db.session.query(User).filter(User.id.in_(user_ids)).all()
            for user in users:
                print(user.name)
        """
        check = QA020NPlusOneQueryPattern()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_detects_async_for_query(self):
        """Query inside async for should also trigger."""
        source = """\
        async def process_items(item_ids):
            async for iid in item_ids:
                item = await db.fetch("SELECT * FROM items WHERE id = $1", iid)
                print(item)
        """
        check = QA020NPlusOneQueryPattern()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# QA-021: Synchronous blocking I/O inside async function
# ---------------------------------------------------------------------------
class TestQA021SyncIOInAsyncContext:
    def test_detects_time_sleep_in_async(self):
        """time.sleep() inside async function should trigger QA-021."""
        source = """\
        import time

        async def handler():
            time.sleep(1)
        """
        check = QA021SyncIOInAsyncContext()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-021"
        assert "time.sleep" in findings[0].message

    def test_detects_requests_in_async(self):
        """requests.get() inside async function should trigger QA-021."""
        source = """\
        import requests

        async def fetch():
            resp = requests.get("https://example.com")
            return resp.json()
        """
        check = QA021SyncIOInAsyncContext()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert "requests.get" in findings[0].message

    def test_detects_open_in_async(self):
        """open() inside async function should trigger QA-021."""
        source = """\
        async def read_file():
            f = open("data.txt")
            return f.read()
        """
        check = QA021SyncIOInAsyncContext()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert "open()" in findings[0].message

    def test_detects_path_read_text_in_async(self):
        """Path.read_text() inside async function should trigger."""
        source = """\
        from pathlib import Path

        async def read_config():
            data = Path("config.json").read_text()
            return data
        """
        check = QA021SyncIOInAsyncContext()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert "read_text" in findings[0].message

    def test_clean_async_sleep(self):
        """asyncio.sleep() inside async function is clean."""
        source = """\
        import asyncio

        async def handler():
            await asyncio.sleep(1)
        """
        check = QA021SyncIOInAsyncContext()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_sync_function(self):
        """Blocking I/O in a normal (non-async) function is not flagged."""
        source = """\
        import time

        def handler():
            time.sleep(1)
        """
        check = QA021SyncIOInAsyncContext()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-022: Using print() or basic logging instead of structured logging
# ---------------------------------------------------------------------------
class TestQA022MissingStructuredLogging:
    def test_detects_print_usage(self):
        """Files using print() without structured logging should trigger."""
        source = """\
        def process():
            print("Processing started")
            do_work()
            print("Done")
        """
        check = QA022MissingStructuredLogging()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "handler.py")
        )
        # With only 1 file using print, it reports per-file
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-022"

    def test_detects_multiple_print_files(self):
        """Many files using print() generates a project-level finding."""
        files = {
            "a.py": "def f(): print('a')\n",
            "b.py": "def f(): print('b')\n",
            "c.py": "def f(): print('c')\n",
        }
        check = QA022MissingStructuredLogging()
        source_files = _make_multi_source_files(files)
        findings = check.run(FAKE_PROJECT, source_files)
        assert len(findings) >= 1
        assert "3" in findings[0].message or "print()" in findings[0].message

    def test_clean_with_structlog(self):
        """Project using structlog should not trigger QA-022."""
        source = """\
        import structlog

        logger = structlog.get_logger()

        def process():
            logger.info("Processing started")
        """
        check = QA022MissingStructuredLogging()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_json_logger(self):
        """Project using python_json_logger should not trigger."""
        source = """\
        from pythonjsonlogger import jsonlogger
        import logging

        handler = logging.StreamHandler()
        handler.setFormatter(jsonlogger.JsonFormatter())
        """
        check = QA022MissingStructuredLogging()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_test_files_ignored(self):
        """Print in test files should not trigger QA-022."""
        source = """\
        def test_something():
            print("test output")
        """
        check = QA022MissingStructuredLogging()
        findings = check.run(
            FAKE_PROJECT, _make_source_files(source, "test_module.py")
        )
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-023: No request tracing or correlation ID support
# ---------------------------------------------------------------------------
class TestQA023NoRequestTracing:
    def test_detects_web_without_tracing(self):
        """A web service without tracing should trigger QA-023."""
        source = """\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/")
        def index():
            return {"hello": "world"}
        """
        check = QA023NoRequestTracing()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-023"
        assert findings[0].severity == Severity.INFO

    def test_clean_with_opentelemetry(self):
        """A service using opentelemetry should not trigger."""
        source = """\
        from fastapi import FastAPI
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        app = FastAPI()
        FastAPIInstrumentor.instrument_app(app)
        """
        check = QA023NoRequestTracing()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_request_id(self):
        """A service with x-request-id middleware is clean."""
        source = """\
        from fastapi import FastAPI, Request

        app = FastAPI()

        @app.middleware("http")
        async def add_request_id(request: Request, call_next):
            request_id = request.headers.get("x-request-id", "")
            response = await call_next(request)
            response.headers["x-request-id"] = request_id
            return response
        """
        check = QA023NoRequestTracing()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_web_project_ignored(self):
        """Non-web projects should not trigger."""
        source = """\
        def calculate():
            return 42
        """
        check = QA023NoRequestTracing()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-024: No application metrics instrumentation detected
# ---------------------------------------------------------------------------
class TestQA024MissingMetrics:
    def test_detects_web_without_metrics(self):
        """A web service without metrics should trigger QA-024."""
        source = """\
        from flask import Flask

        app = Flask(__name__)

        @app.route("/")
        def index():
            return "Hello"
        """
        check = QA024MissingMetrics()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-024"
        assert findings[0].severity == Severity.INFO

    def test_clean_with_prometheus(self):
        """A service using prometheus_client should not trigger."""
        source = """\
        from flask import Flask
        from prometheus_client import Counter, generate_latest

        app = Flask(__name__)
        request_count = Counter("requests_total", "Total requests")
        """
        check = QA024MissingMetrics()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_statsd(self):
        """A service using statsd should not trigger."""
        source = """\
        from flask import Flask
        import statsd

        app = Flask(__name__)
        stats = statsd.StatsClient()
        """
        check = QA024MissingMetrics()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_web_project_ignored(self):
        """Non-web projects should not trigger."""
        source = """\
        def process():
            return 42
        """
        check = QA024MissingMetrics()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# QA-025: No external error reporting integration
# ---------------------------------------------------------------------------
class TestQA025NoErrorReporting:
    def test_detects_service_without_error_reporting(self):
        """A service without Sentry/Bugsnag/etc. should trigger QA-025."""
        source = """\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/")
        def index():
            return {"hello": "world"}
        """
        check = QA025NoErrorReporting()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) >= 1
        assert findings[0].check_id == "QA-025"
        assert findings[0].severity == Severity.WARNING

    def test_clean_with_sentry(self):
        """A service using sentry_sdk should not trigger."""
        source = """\
        import sentry_sdk
        from fastapi import FastAPI

        sentry_sdk.init(dsn="https://examplePublicKey@o0.ingest.sentry.io/0")
        app = FastAPI()
        """
        check = QA025NoErrorReporting()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_clean_with_bugsnag(self):
        """A service using bugsnag should not trigger."""
        source = """\
        import bugsnag
        from flask import Flask

        bugsnag.configure(api_key="YOUR_API_KEY")
        app = Flask(__name__)
        """
        check = QA025NoErrorReporting()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0

    def test_non_service_ignored(self):
        """Non-service projects should not trigger."""
        source = """\
        def helper():
            return 42
        """
        check = QA025NoErrorReporting()
        findings = check.run(FAKE_PROJECT, _make_source_files(source))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Cross-cutting: check metadata
# ---------------------------------------------------------------------------
class TestCheckMetadata:
    """Verify that all checks have correct metadata."""

    def test_all_checks_have_unique_ids(self):
        """Every QA check should have a unique check_id."""
        from devnog.qa.checks import ALL_QA_CHECKS

        ids = [cls().check_id for cls in ALL_QA_CHECKS]
        assert len(ids) == len(set(ids)), f"Duplicate check IDs: {ids}"

    def test_all_checks_have_prod_readiness_category(self):
        """Every QA check should be in the PROD_READINESS category."""
        from devnog.qa.checks import ALL_QA_CHECKS

        for cls in ALL_QA_CHECKS:
            check = cls()
            assert check.category == Category.PROD_READINESS, (
                f"{check.check_id} has category {check.category}"
            )

    def test_all_checks_have_description(self):
        """Every QA check should have a non-empty description."""
        from devnog.qa.checks import ALL_QA_CHECKS

        for cls in ALL_QA_CHECKS:
            check = cls()
            assert check.description, f"{check.check_id} has no description"

    def test_all_checks_count(self):
        """There should be exactly 25 QA checks registered."""
        from devnog.qa.checks import ALL_QA_CHECKS

        assert len(ALL_QA_CHECKS) == 25
