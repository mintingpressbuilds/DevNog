"""Tests for error handling checks ERR-001 through ERR-008."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from devnog.scanner.checks.error_handling import (
    ERR001BareExcept,
    ERR002SilentExcept,
    ERR003IOWithoutTry,
    ERR004APIWithoutTry,
    ERR005NoGlobalHandler,
    ERR006AsyncNoCancelHandler,
    ERR007HTTPNoTimeout,
    ERR008ReturnNoneOnError,
)
from devnog.core.models import Category, Finding, Severity


FAKE_PATH = Path("test_file.py")


def _run_check(check, source: str, file_path: Path | None = None) -> list[Finding]:
    """Helper: parse source and run a check."""
    fp = file_path or FAKE_PATH
    tree = ast.parse(textwrap.dedent(source))
    return check.run(fp, textwrap.dedent(source), tree)


# ---------------------------------------------------------------------------
# ERR-001: Bare except
# ---------------------------------------------------------------------------
class TestERR001BareExcept:
    def test_detects_bare_except(self):
        """A bare except: should trigger ERR-001."""
        source = """\
try:
    risky()
except:
    handle_error()
"""
        check = ERR001BareExcept()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-001"
        assert "bare except" in findings[0].message.lower()

    def test_clean_code_typed_except(self):
        """except Exception should not trigger ERR-001."""
        source = """\
try:
    risky()
except Exception as e:
    handle_error(e)
"""
        check = ERR001BareExcept()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_specific_exception(self):
        """except ValueError should not trigger ERR-001."""
        source = """\
try:
    int("abc")
except ValueError:
    pass
"""
        check = ERR001BareExcept()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_multiple_bare_excepts(self):
        """Multiple bare except: blocks should each be detected."""
        source = """\
try:
    a()
except:
    pass

try:
    b()
except:
    pass
"""
        check = ERR001BareExcept()
        findings = _run_check(check, source)
        assert len(findings) >= 2


# ---------------------------------------------------------------------------
# ERR-002: Silent except (except: pass)
# ---------------------------------------------------------------------------
class TestERR002SilentExcept:
    def test_detects_except_pass(self):
        """except: pass should trigger ERR-002."""
        source = """\
try:
    risky()
except:
    pass
"""
        check = ERR002SilentExcept()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-002"
        assert "silent" in findings[0].message.lower()

    def test_detects_except_ellipsis(self):
        """except: ... should trigger ERR-002."""
        source = """\
try:
    risky()
except:
    ...
"""
        check = ERR002SilentExcept()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_except_with_logging(self):
        """except with actual handling should not trigger ERR-002."""
        source = """\
try:
    risky()
except Exception as e:
    logger.error(e)
    raise
"""
        check = ERR002SilentExcept()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_except_with_multiple_statements(self):
        """except with multiple statements (not just pass) should not trigger."""
        source = """\
try:
    risky()
except Exception as e:
    logger.error(e)
    cleanup()
"""
        check = ERR002SilentExcept()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ERR-003: I/O without try
# ---------------------------------------------------------------------------
class TestERR003IOWithoutTry:
    def test_detects_open_without_try(self):
        """open() outside try/except should trigger ERR-003."""
        source = """\
def read_file():
    f = open("data.txt")
    return f.read()
"""
        check = ERR003IOWithoutTry()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-003"

    def test_clean_code_open_in_try(self):
        """open() inside try/except should not trigger ERR-003."""
        source = """\
def read_file():
    try:
        f = open("data.txt")
        return f.read()
    except IOError:
        return None
"""
        check = ERR003IOWithoutTry()
        findings = _run_check(check, source)
        # The open() is inside the try range, so should not be flagged
        assert len(findings) == 0

    def test_detects_write_without_try(self):
        """write() outside try should trigger ERR-003."""
        source = """\
def save_data(data):
    f = open("output.txt", "w")
    f.write(data)
"""
        check = ERR003IOWithoutTry()
        findings = _run_check(check, source)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# ERR-004: API call without try
# ---------------------------------------------------------------------------
class TestERR004APIWithoutTry:
    def test_detects_requests_get_without_try(self):
        """requests.get() outside try should trigger ERR-004."""
        source = """\
import requests

def fetch():
    response = requests.get("https://api.example.com/data")
    return response.json()
"""
        check = ERR004APIWithoutTry()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-004"

    def test_clean_code_in_try(self):
        """requests.get() inside try should not trigger ERR-004."""
        source = """\
import requests

def fetch():
    try:
        response = requests.get("https://api.example.com/data")
        return response.json()
    except requests.RequestException:
        return None
"""
        check = ERR004APIWithoutTry()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_detects_httpx_post_without_try(self):
        """httpx.post() outside try should trigger ERR-004."""
        source = """\
import httpx

def create():
    response = httpx.post("https://api.example.com/data", json={})
    return response.json()
"""
        check = ERR004APIWithoutTry()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_no_http_calls(self):
        """Code without HTTP calls should not trigger ERR-004."""
        source = """\
def compute(x):
    return x * 2
"""
        check = ERR004APIWithoutTry()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ERR-005: No global exception handler
# ---------------------------------------------------------------------------
class TestERR005NoGlobalHandler:
    def test_detects_no_global_handler_in_main(self):
        """main.py without global handler should trigger ERR-005."""
        source = """\
def main():
    run_app()

if __name__ == "__main__":
    main()
"""
        check = ERR005NoGlobalHandler()
        findings = _run_check(check, source, file_path=Path("main.py"))
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-005"

    def test_clean_code_with_handler(self):
        """main.py with exception_handler should not trigger ERR-005."""
        source = """\
def exception_handler(exc):
    log(exc)

def main():
    run_app()
"""
        check = ERR005NoGlobalHandler()
        findings = _run_check(check, source, file_path=Path("main.py"))
        assert len(findings) == 0

    def test_clean_code_with_try_in_main(self):
        """main.py with try/except in __main__ block should not trigger."""
        source = """\
def main():
    run_app()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
"""
        check = ERR005NoGlobalHandler()
        findings = _run_check(check, source, file_path=Path("main.py"))
        assert len(findings) == 0

    def test_non_main_file_skipped(self):
        """Non-entry-point files should not trigger ERR-005."""
        source = """\
def helper():
    pass
"""
        check = ERR005NoGlobalHandler()
        findings = _run_check(check, source, file_path=Path("utils.py"))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ERR-006: Async without CancelledError handling
# ---------------------------------------------------------------------------
class TestERR006AsyncNoCancelHandler:
    def test_detects_missing_cancel_handler(self):
        """Async function with try but no CancelledError handler should trigger."""
        source = """\
import asyncio

async def fetch_data():
    try:
        result = await asyncio.sleep(1)
        return result
    except Exception as e:
        print(e)
"""
        check = ERR006AsyncNoCancelHandler()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-006"

    def test_clean_code_with_cancel_handler(self):
        """Async with CancelledError handler should not trigger ERR-006."""
        source = """\
import asyncio

async def fetch_data():
    try:
        result = await asyncio.sleep(1)
        return result
    except asyncio.CancelledError:
        raise
    except Exception as e:
        print(e)
"""
        check = ERR006AsyncNoCancelHandler()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_try_in_async(self):
        """Async without any try block should not trigger ERR-006."""
        source = """\
async def simple():
    await asyncio.sleep(1)
    return 42
"""
        check = ERR006AsyncNoCancelHandler()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ERR-007: HTTP call without timeout
# ---------------------------------------------------------------------------
class TestERR007HTTPNoTimeout:
    def test_detects_missing_timeout(self):
        """requests.get() without timeout should trigger ERR-007."""
        source = """\
import requests
response = requests.get("https://api.example.com/data")
"""
        check = ERR007HTTPNoTimeout()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-007"
        assert "timeout" in findings[0].message.lower()

    def test_clean_code_with_timeout(self):
        """requests.get() with timeout should not trigger ERR-007."""
        source = """\
import requests
response = requests.get("https://api.example.com/data", timeout=30)
"""
        check = ERR007HTTPNoTimeout()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_detects_post_without_timeout(self):
        """requests.post() without timeout should trigger ERR-007."""
        source = """\
import requests
response = requests.post("https://api.example.com/data", json={})
"""
        check = ERR007HTTPNoTimeout()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_non_http_lib(self):
        """get() on non-HTTP library should not trigger ERR-007."""
        source = """\
cache.get("key")
"""
        check = ERR007HTTPNoTimeout()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ERR-008: Return None on error
# ---------------------------------------------------------------------------
class TestERR008ReturnNoneOnError:
    def test_detects_return_none_in_except(self):
        """return None in except block should trigger ERR-008."""
        source = """\
def fetch(url):
    try:
        return do_fetch(url)
    except Exception:
        return None
"""
        check = ERR008ReturnNoneOnError()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "ERR-008"

    def test_detects_bare_return_in_except(self):
        """Bare return (implicitly None) in except should trigger ERR-008."""
        source = """\
def fetch(url):
    try:
        return do_fetch(url)
    except Exception:
        return
"""
        check = ERR008ReturnNoneOnError()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_reraise(self):
        """raise in except block should not trigger ERR-008."""
        source = """\
def fetch(url):
    try:
        return do_fetch(url)
    except Exception:
        raise
"""
        check = ERR008ReturnNoneOnError()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_return_value(self):
        """Returning an actual value in except should not trigger ERR-008."""
        source = """\
def fetch(url):
    try:
        return do_fetch(url)
    except Exception:
        return {"error": "failed"}
"""
        check = ERR008ReturnNoneOnError()
        findings = _run_check(check, source)
        assert len(findings) == 0
