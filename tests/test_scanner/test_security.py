"""Tests for security checks SEC-001 through SEC-012."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from devnog.scanner.checks.security import (
    SEC001HardcodedSecrets,
    SEC002SQLInjection,
    SEC003MissingRateLimiting,
    SEC004DangerousEval,
    SEC005OpenCORS,
    SEC006DebugTrue,
    SEC007JWTNoExpiry,
    SEC008TokensInURL,
    SEC009WeakHashing,
    SEC010PathTraversal,
    SEC011MissingInputValidation,
    SEC012SubprocessShell,
)
from devnog.core.models import Category, Finding, Severity


FAKE_PATH = Path("test_file.py")


def _run_check(check, source: str) -> list[Finding]:
    """Helper: parse source and run a check."""
    tree = ast.parse(textwrap.dedent(source))
    return check.run(FAKE_PATH, textwrap.dedent(source), tree)


# ---------------------------------------------------------------------------
# SEC-001: Hardcoded secrets
# ---------------------------------------------------------------------------
class TestSEC001HardcodedSecrets:
    def test_detects_hardcoded_api_key(self):
        """A hardcoded API key should trigger SEC-001."""
        source = """\
api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678"
"""
        check = SEC001HardcodedSecrets()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-001"

    def test_detects_hardcoded_password(self):
        """A hardcoded password should trigger SEC-001."""
        source = """\
password = "super-secret-password-123"
"""
        check = SEC001HardcodedSecrets()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_detects_hardcoded_secret_key(self):
        """A hardcoded secret_key should trigger SEC-001."""
        source = """\
secret_key = "my-secret-key-value-here"
"""
        check = SEC001HardcodedSecrets()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_env_var(self):
        """Reading from environment should not trigger SEC-001."""
        source = """\
import os
api_key = os.environ["API_KEY"]
"""
        check = SEC001HardcodedSecrets()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_non_secret_var(self):
        """Non-secret variable names should not trigger SEC-001."""
        source = """\
app_name = "my-application"
max_retries = 3
"""
        check = SEC001HardcodedSecrets()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_short_values_ignored(self):
        """Very short values (<=3 chars) should not trigger."""
        source = """\
password = "ab"
"""
        check = SEC001HardcodedSecrets()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-002: SQL injection
# ---------------------------------------------------------------------------
class TestSEC002SQLInjection:
    def test_detects_fstring_sql(self):
        """f-string in SQL query should trigger SEC-002."""
        source = """\
def query(name):
    q = f"SELECT * FROM users WHERE name = '{name}'"
    return q
"""
        check = SEC002SQLInjection()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-002"
        assert "f-string" in findings[0].message

    def test_detects_format_sql(self):
        """str.format() in SQL query should trigger SEC-002."""
        source = """\
def query(email):
    q = "SELECT * FROM users WHERE email = '{}'".format(email)
    return q
"""
        check = SEC002SQLInjection()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert "format" in findings[0].message.lower()

    def test_detects_percent_format_sql(self):
        """% formatting in SQL query should trigger SEC-002."""
        source = """\
def query(uid):
    q = "DELETE FROM users WHERE id = %s" % uid
    return q
"""
        check = SEC002SQLInjection()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_parameterized(self):
        """Parameterized queries should not trigger SEC-002."""
        source = """\
def query(name):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
"""
        check = SEC002SQLInjection()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_sql(self):
        """Regular f-strings without SQL should not trigger SEC-002."""
        source = """\
def greet(name):
    return f"Hello, {name}!"
"""
        check = SEC002SQLInjection()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-003: Missing rate limiting
# ---------------------------------------------------------------------------
class TestSEC003MissingRateLimiting:
    def test_detects_missing_rate_limit(self):
        """Route without rate limiting should trigger SEC-003."""
        source = """\
from flask import Flask
app = Flask(__name__)

@app.route("/api/users")
def get_users():
    return []
"""
        check = SEC003MissingRateLimiting()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-003"

    def test_clean_code_has_rate_limit(self):
        """File with rate_limit reference should not trigger SEC-003."""
        source = """\
from flask import Flask
from flask_limiter import rate_limit

app = Flask(__name__)

@app.route("/api/users")
def get_users():
    return []
"""
        check = SEC003MissingRateLimiting()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_routes(self):
        """File without route decorators should not trigger SEC-003."""
        source = """\
def helper():
    return 42
"""
        check = SEC003MissingRateLimiting()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-004: Dangerous eval/exec
# ---------------------------------------------------------------------------
class TestSEC004DangerousEval:
    def test_detects_eval(self):
        """eval() usage should trigger SEC-004."""
        source = """\
result = eval(user_input)
"""
        check = SEC004DangerousEval()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-004"
        assert "eval" in findings[0].message

    def test_detects_exec(self):
        """exec() usage should trigger SEC-004."""
        source = """\
exec(code_string)
"""
        check = SEC004DangerousEval()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert "exec" in findings[0].message

    def test_detects_pickle_loads(self):
        """pickle.loads() should trigger SEC-004."""
        source = """\
import pickle
data = pickle.loads(raw_bytes)
"""
        check = SEC004DangerousEval()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert "pickle" in findings[0].message

    def test_clean_code(self):
        """ast.literal_eval() should not trigger SEC-004."""
        source = """\
import ast
result = ast.literal_eval(user_input)
"""
        check = SEC004DangerousEval()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_json_loads(self):
        """json.loads() should not trigger SEC-004."""
        source = """\
import json
data = json.loads(raw_string)
"""
        check = SEC004DangerousEval()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-005: Open CORS
# ---------------------------------------------------------------------------
class TestSEC005OpenCORS:
    def test_detects_wildcard_origins(self):
        """allow_origins=["*"] should trigger SEC-005."""
        source = """\
app.add_middleware(CORSMiddleware, allow_origins=["*"])
"""
        check = SEC005OpenCORS()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-005"

    def test_detects_allow_all_true(self):
        """CORS_ALLOW_ALL_ORIGINS = True should trigger SEC-005."""
        source = """\
CORS_ALLOW_ALL_ORIGINS = True
"""
        check = SEC005OpenCORS()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_specific_origins(self):
        """Specific CORS origins should not trigger SEC-005."""
        source = """\
app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])
"""
        check = SEC005OpenCORS()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_cors(self):
        """Code without CORS should not trigger SEC-005."""
        source = """\
def handler():
    return {"status": "ok"}
"""
        check = SEC005OpenCORS()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-006: DEBUG = True
# ---------------------------------------------------------------------------
class TestSEC006DebugTrue:
    def test_detects_debug_true(self):
        """DEBUG = True should trigger SEC-006."""
        source = """\
DEBUG = True
"""
        check = SEC006DebugTrue()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-006"

    def test_clean_code_debug_false(self):
        """DEBUG = False should not trigger SEC-006."""
        source = """\
DEBUG = False
"""
        check = SEC006DebugTrue()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_env_var(self):
        """DEBUG from env var should not trigger SEC-006."""
        source = """\
import os
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
"""
        check = SEC006DebugTrue()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_different_var_name(self):
        """A different variable set to True should not trigger SEC-006."""
        source = """\
VERBOSE = True
"""
        check = SEC006DebugTrue()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-007: JWT without expiry
# ---------------------------------------------------------------------------
class TestSEC007JWTNoExpiry:
    def test_detects_jwt_without_exp(self):
        """JWT encode without exp claim should trigger SEC-007."""
        source = """\
import jwt
token = jwt.encode({"user_id": 123}, "secret", algorithm="HS256")
"""
        check = SEC007JWTNoExpiry()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-007"

    def test_clean_code_jwt_with_exp(self):
        """JWT encode with exp claim should not trigger SEC-007."""
        source = """\
import jwt
token = jwt.encode({"user_id": 123, "exp": 1700000000}, "secret", algorithm="HS256")
"""
        check = SEC007JWTNoExpiry()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_jwt(self):
        """Non-JWT encode calls should not trigger SEC-007."""
        source = """\
data = base64.encode(payload)
"""
        check = SEC007JWTNoExpiry()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-008: Tokens in URL
# ---------------------------------------------------------------------------
class TestSEC008TokensInURL:
    def test_detects_token_in_url(self):
        """A URL with ?token= should trigger SEC-008."""
        source = """\
url = "https://api.example.com/data?token=abc123"
response = requests.get(url)
"""
        check = SEC008TokensInURL()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-008"

    def test_clean_code_header_auth(self):
        """Auth in headers should not trigger SEC-008."""
        source = """\
headers = {"Authorization": "Bearer token123"}
response = requests.get(url, headers=headers)
"""
        check = SEC008TokensInURL()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_sensitive_params(self):
        """URLs without sensitive params should not trigger SEC-008."""
        source = """\
url = "https://api.example.com/data?page=1&limit=10"
"""
        check = SEC008TokensInURL()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-009: Weak hashing
# ---------------------------------------------------------------------------
class TestSEC009WeakHashing:
    def test_detects_md5(self):
        """hashlib.md5() should trigger SEC-009."""
        source = """\
import hashlib
h = hashlib.md5(data.encode())
"""
        check = SEC009WeakHashing()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-009"
        assert "md5" in findings[0].message.lower()

    def test_detects_sha1(self):
        """hashlib.sha1() should trigger SEC-009."""
        source = """\
import hashlib
h = hashlib.sha1(data.encode())
"""
        check = SEC009WeakHashing()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_detects_hashlib_new_md5(self):
        """hashlib.new('md5') should trigger SEC-009."""
        source = """\
import hashlib
h = hashlib.new("md5", data.encode())
"""
        check = SEC009WeakHashing()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_sha256(self):
        """hashlib.sha256() should not trigger SEC-009."""
        source = """\
import hashlib
h = hashlib.sha256(data.encode())
"""
        check = SEC009WeakHashing()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-010: Path traversal
# ---------------------------------------------------------------------------
class TestSEC010PathTraversal:
    def test_detects_fstring_in_open(self):
        """f-string path in open() should trigger SEC-010."""
        source = """\
def read_file(filename):
    with open(f"/data/{filename}") as f:
        return f.read()
"""
        check = SEC010PathTraversal()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-010"

    def test_detects_concatenated_path(self):
        """Concatenated path in open() should trigger SEC-010."""
        source = """\
def read_file(filename):
    with open("/data/" + filename) as f:
        return f.read()
"""
        check = SEC010PathTraversal()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_static_path(self):
        """A static string path in open() should not trigger SEC-010."""
        source = """\
def read_config():
    with open("config.json") as f:
        return f.read()
"""
        check = SEC010PathTraversal()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-011: Missing input validation
# ---------------------------------------------------------------------------
class TestSEC011MissingInputValidation:
    def test_detects_missing_validation(self):
        """Route accessing request data without validation should trigger SEC-011."""
        source = """\
@app.post("/users")
def create_user():
    data = request.json
    name = data["name"]
    return {"status": "ok"}
"""
        check = SEC011MissingInputValidation()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-011"

    def test_clean_code_with_validation(self):
        """File mentioning pydantic should not trigger SEC-011."""
        source = """\
from pydantic import BaseModel

class UserCreate(BaseModel):
    name: str

@app.post("/users")
def create_user(user: UserCreate):
    return {"status": "ok"}
"""
        check = SEC011MissingInputValidation()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_routes(self):
        """File without route decorators should not trigger SEC-011."""
        source = """\
def helper():
    return 42
"""
        check = SEC011MissingInputValidation()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SEC-012: subprocess shell=True
# ---------------------------------------------------------------------------
class TestSEC012SubprocessShell:
    def test_detects_shell_true(self):
        """subprocess.run(shell=True) should trigger SEC-012."""
        source = """\
import subprocess
result = subprocess.run("ls -la", shell=True, capture_output=True)
"""
        check = SEC012SubprocessShell()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "SEC-012"
        assert "shell" in findings[0].message.lower()

    def test_detects_os_system(self):
        """os.system() should trigger SEC-012."""
        source = """\
import os
os.system("rm -rf /tmp/cache")
"""
        check = SEC012SubprocessShell()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert "os.system" in findings[0].message

    def test_detects_popen_shell_true(self):
        """subprocess.Popen(shell=True) should trigger SEC-012."""
        source = """\
import subprocess
proc = subprocess.Popen("echo hello", shell=True)
"""
        check = SEC012SubprocessShell()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_shell_false(self):
        """subprocess.run(shell=False) should not trigger SEC-012."""
        source = """\
import subprocess
result = subprocess.run(["ls", "-la"], shell=False, capture_output=True)
"""
        check = SEC012SubprocessShell()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_no_shell_kwarg(self):
        """subprocess.run() without shell= keyword should not trigger SEC-012."""
        source = """\
import subprocess
result = subprocess.run(["ls", "-la"], capture_output=True)
"""
        check = SEC012SubprocessShell()
        findings = _run_check(check, source)
        assert len(findings) == 0
