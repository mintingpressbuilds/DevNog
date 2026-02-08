"""Tests for rule-based fix generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.fix.rule_fixer import RuleBasedFixer
from devnog.core.models import Finding, Category, Severity, FixType, FixProposal


@pytest.fixture
def fixer() -> RuleBasedFixer:
    return RuleBasedFixer()


def _make_finding(
    check_id: str,
    line: int,
    file: str = "app.py",
    category: Category = Category.SECURITY,
    severity: Severity = Severity.CRITICAL,
    fix_type: FixType = FixType.RULE_BASED,
    message: str = "test finding",
    suggestion: str = "",
) -> Finding:
    return Finding(
        check_id=check_id,
        category=category,
        severity=severity,
        message=message,
        file=Path(file),
        line=line,
        fix_type=fix_type,
        suggestion=suggestion,
    )


# ---------------------------------------------------------------------------
# SEC-001: Hardcoded secret -> env var
# ---------------------------------------------------------------------------
class TestFixSEC001:
    def test_generates_env_var_fix(self, fixer: RuleBasedFixer):
        """SEC-001 fix should replace hardcoded value with os.environ."""
        source = 'api_key = "sk-proj-abc123def456ghi789"\n'
        finding = _make_finding("SEC-001", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert isinstance(proposal, FixProposal)
        assert "os.environ" in proposal.new_code
        assert proposal.confidence == "high"

    def test_returns_none_for_non_matching(self, fixer: RuleBasedFixer):
        """SEC-001 fix should return None if line doesn't match pattern."""
        source = "import os\n"
        finding = _make_finding("SEC-001", line=1)
        proposal = fixer.try_fix(finding, source)
        assert proposal is None

    def test_manual_steps_include_env_export(self, fixer: RuleBasedFixer):
        """SEC-001 fix should include manual step for setting env var."""
        source = 'password = "my-secret-password"\n'
        finding = _make_finding("SEC-001", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert any("export" in step.lower() or "environment" in step.lower()
                    for step in proposal.manual_steps)


# ---------------------------------------------------------------------------
# SEC-004: eval -> ast.literal_eval
# ---------------------------------------------------------------------------
class TestFixSEC004:
    def test_replaces_eval_with_literal_eval(self, fixer: RuleBasedFixer):
        """SEC-004 fix should replace eval() with ast.literal_eval()."""
        source = 'result = eval(user_input)\n'
        finding = _make_finding("SEC-004", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "ast.literal_eval" in proposal.new_code
        assert "eval(" not in proposal.new_code or "literal_eval" in proposal.new_code

    def test_returns_none_if_already_literal_eval(self, fixer: RuleBasedFixer):
        """Should return None if already using ast.literal_eval."""
        source = 'result = ast.literal_eval(user_input)\n'
        finding = _make_finding("SEC-004", line=1)
        proposal = fixer.try_fix(finding, source)
        assert proposal is None


# ---------------------------------------------------------------------------
# SEC-005: Open CORS -> restricted
# ---------------------------------------------------------------------------
class TestFixSEC005:
    def test_restricts_wildcard_cors(self, fixer: RuleBasedFixer):
        """SEC-005 fix should replace ["*"] with specific domain."""
        source = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
        finding = _make_finding("SEC-005", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "*" not in proposal.new_code
        assert "yourdomain.com" in proposal.new_code


# ---------------------------------------------------------------------------
# SEC-006: DEBUG = True -> env var
# ---------------------------------------------------------------------------
class TestFixSEC006:
    def test_replaces_debug_true_with_env(self, fixer: RuleBasedFixer):
        """SEC-006 fix should replace DEBUG = True with env var check."""
        source = 'DEBUG = True\n'
        finding = _make_finding("SEC-006", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "os.environ" in proposal.new_code
        assert "True" not in proposal.new_code


# ---------------------------------------------------------------------------
# SEC-009: Weak hash -> SHA256
# ---------------------------------------------------------------------------
class TestFixSEC009:
    def test_replaces_md5_with_sha256(self, fixer: RuleBasedFixer):
        """SEC-009 fix should replace hashlib.md5 with hashlib.sha256."""
        source = 'h = hashlib.md5(data.encode())\n'
        finding = _make_finding("SEC-009", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "sha256" in proposal.new_code
        assert "md5" not in proposal.new_code

    def test_replaces_sha1_with_sha256(self, fixer: RuleBasedFixer):
        """SEC-009 fix should replace hashlib.sha1 with hashlib.sha256."""
        source = 'h = hashlib.sha1(data.encode())\n'
        finding = _make_finding("SEC-009", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "sha256" in proposal.new_code


# ---------------------------------------------------------------------------
# SEC-012: subprocess shell=True -> shell=False
# ---------------------------------------------------------------------------
class TestFixSEC012:
    def test_replaces_shell_true(self, fixer: RuleBasedFixer):
        """SEC-012 fix should replace shell=True with shell=False."""
        source = 'result = subprocess.run("ls", shell=True, capture_output=True)\n'
        finding = _make_finding("SEC-012", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "shell=False" in proposal.new_code
        assert "shell=True" not in proposal.new_code

    def test_replaces_os_system(self, fixer: RuleBasedFixer):
        """SEC-012 fix should replace os.system() with subprocess.run()."""
        source = 'os.system("ls -la")\n'
        finding = _make_finding("SEC-012", line=1)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "subprocess.run" in proposal.new_code


# ---------------------------------------------------------------------------
# ERR-001: Bare except -> except Exception as e
# ---------------------------------------------------------------------------
class TestFixERR001:
    def test_adds_exception_type(self, fixer: RuleBasedFixer):
        """ERR-001 fix should add Exception type to bare except."""
        source = 'except:\n    handle_error()\n'
        finding = _make_finding("ERR-001", line=1, category=Category.ERROR_HANDLING)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "except Exception as e:" in proposal.new_code


# ---------------------------------------------------------------------------
# ERR-002: Silent except -> logging
# ---------------------------------------------------------------------------
class TestFixERR002:
    def test_replaces_pass_with_logging(self, fixer: RuleBasedFixer):
        """ERR-002 fix should replace pass with logger.exception(e)."""
        source = 'except:\n    pass\n'
        finding = _make_finding("ERR-002", line=1, category=Category.ERROR_HANDLING)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "logger" in proposal.new_code or "Exception" in proposal.new_code


# ---------------------------------------------------------------------------
# ERR-007: HTTP no timeout -> add timeout=30
# ---------------------------------------------------------------------------
class TestFixERR007:
    def test_adds_timeout(self, fixer: RuleBasedFixer):
        """ERR-007 fix should add timeout=30 to HTTP call."""
        source = 'response = requests.get("https://api.example.com")\n'
        finding = _make_finding("ERR-007", line=1, category=Category.ERROR_HANDLING)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "timeout=30" in proposal.new_code


# ---------------------------------------------------------------------------
# ERR-008: Return None on error -> raise
# ---------------------------------------------------------------------------
class TestFixERR008:
    def test_replaces_return_none_with_raise(self, fixer: RuleBasedFixer):
        """ERR-008 fix should replace return None with raise."""
        source = '    return None\n'
        finding = _make_finding("ERR-008", line=1, category=Category.ERROR_HANDLING)
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert "raise" in proposal.new_code


# ---------------------------------------------------------------------------
# CQ-004: Unused import -> remove
# ---------------------------------------------------------------------------
class TestFixCQ004:
    def test_removes_unused_import(self, fixer: RuleBasedFixer):
        """CQ-004 fix should produce proposal to remove the import line."""
        source = 'import sys\nimport os\n\nprint(os.getcwd())\n'
        finding = _make_finding(
            "CQ-004", line=1, category=Category.CODE_QUALITY,
            severity=Severity.INFO,
        )
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert proposal.new_code == ""  # Line should be deleted
        assert proposal.original_code == "import sys"


# ---------------------------------------------------------------------------
# CQ-009: Star import -> flag for review
# ---------------------------------------------------------------------------
class TestFixCQ009:
    def test_flags_star_import(self, fixer: RuleBasedFixer):
        """CQ-009 fix should flag star import for review."""
        source = 'from os.path import *\n'
        finding = _make_finding(
            "CQ-009", line=1, category=Category.CODE_QUALITY,
            severity=Severity.WARNING,
        )
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert proposal.requires_review is True
        assert len(proposal.manual_steps) > 0


# ---------------------------------------------------------------------------
# CQ-010: Dead code -> remove
# ---------------------------------------------------------------------------
class TestFixCQ010:
    def test_removes_dead_code(self, fixer: RuleBasedFixer):
        """CQ-010 fix should produce proposal to remove unreachable line."""
        source = 'def func():\n    return 42\n    print("dead")\n'
        finding = _make_finding(
            "CQ-010", line=3, category=Category.CODE_QUALITY,
            severity=Severity.INFO,
        )
        proposal = fixer.try_fix(finding, source)

        assert proposal is not None
        assert proposal.new_code == ""


# ---------------------------------------------------------------------------
# Unsupported check ID
# ---------------------------------------------------------------------------
class TestFixUnsupported:
    def test_returns_none_for_unknown_check(self, fixer: RuleBasedFixer):
        """Unknown check IDs should return None."""
        source = 'x = 1\n'
        finding = _make_finding("UNKNOWN-999", line=1)
        proposal = fixer.try_fix(finding, source)
        assert proposal is None

    def test_returns_none_for_ai_only_check(self, fixer: RuleBasedFixer):
        """Check IDs without rule-based handlers should return None."""
        source = 'def complex_function():\n    pass\n'
        finding = _make_finding("CQ-001", line=1)
        proposal = fixer.try_fix(finding, source)
        assert proposal is None
