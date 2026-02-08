"""Rule-based fix generators for deterministic patterns."""

from __future__ import annotations

import re
from pathlib import Path

from devnog.core.models import Finding, FixProposal


class RuleBasedFixer:
    """Generates deterministic fixes for common patterns."""

    def try_fix(self, finding: Finding, source: str) -> FixProposal | None:
        """Try to generate a rule-based fix. Returns None if not applicable."""
        handler = self._get_handler(finding.check_id)
        if handler:
            return handler(finding, source)
        return None

    def _get_handler(self, check_id: str):
        """Get the fix handler for a check ID."""
        handlers = {
            "SEC-001": self._fix_hardcoded_secret,
            "SEC-004": self._fix_dangerous_eval,
            "SEC-005": self._fix_open_cors,
            "SEC-006": self._fix_debug_true,
            "SEC-009": self._fix_weak_hashing,
            "SEC-012": self._fix_subprocess_shell,
            "ERR-001": self._fix_bare_except,
            "ERR-002": self._fix_silent_except,
            "ERR-007": self._fix_http_no_timeout,
            "ERR-008": self._fix_return_none_on_error,
            "CQ-004": self._fix_unused_import,
            "CQ-009": self._fix_star_import,
            "CQ-010": self._fix_dead_code,
        }
        return handlers.get(check_id)

    def _fix_hardcoded_secret(self, finding: Finding, source: str) -> FixProposal | None:
        """SEC-001: Replace hardcoded secret with os.environ."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        # Match: VAR_NAME = "value" or VAR_NAME = 'value'
        match = re.match(r'^(\s*)([\w]+)\s*=\s*["\'](.+?)["\'](.*)$', line)
        if not match:
            return None

        indent, var_name, value, trailing = match.groups()
        env_var = var_name.upper()
        new_line = f'{indent}{var_name} = os.environ["{env_var}"]'

        # Check if os is already imported
        needs_import = "import os" not in source

        new_code = new_line
        diff = f"- {line}\n+ {new_line}"

        manual_steps = [f'Set environment variable: export {env_var}="<your-value>"']
        if needs_import:
            manual_steps.insert(0, "Add 'import os' to the top of the file")
            # Prepend import to new_code
            new_code = new_line

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description=f"Move {var_name} to environment variable {env_var}",
            diff=diff,
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            manual_steps=manual_steps,
            confidence="high",
            confidence_score=0.95,
            confidence_reason="Deterministic: replace hardcoded value with env var lookup",
        )

    def _fix_dangerous_eval(self, finding: Finding, source: str) -> FixProposal | None:
        """SEC-004: Replace eval() with ast.literal_eval()."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        if "eval(" in line and "literal_eval" not in line:
            new_line = line.replace("eval(", "ast.literal_eval(")
            return FixProposal(
                finding_id=finding.check_id,
                fix_type="rule_based",
                description="Replace eval() with ast.literal_eval()",
                diff=f"- {line}\n+ {new_line}",
                file=finding.file,
                line_start=finding.line,
                line_end=finding.line,
                new_code=new_line,
                original_code=line,
                manual_steps=["Add 'import ast' if not already imported"],
                confidence="high",
                confidence_score=0.85,
                confidence_reason="Safe for literal values; may fail for non-literal expressions",
            )

        return None

    def _fix_open_cors(self, finding: Finding, source: str) -> FixProposal | None:
        """SEC-005: Restrict CORS origins."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]
        new_line = line.replace('["*"]', '["https://yourdomain.com"]')
        new_line = new_line.replace("['*']", "['https://yourdomain.com']")
        new_line = new_line.replace("= True", '= False  # Configure allowed origins explicitly')

        if new_line == line:
            return None

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Restrict CORS to specific origins",
            diff=f"- {line}\n+ {new_line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            manual_steps=["Replace 'https://yourdomain.com' with your actual domain"],
            confidence="high",
            confidence_score=0.90,
        )

    def _fix_debug_true(self, finding: Finding, source: str) -> FixProposal | None:
        """SEC-006: Replace DEBUG=True with env var check."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]
        indent = len(line) - len(line.lstrip())
        new_line = " " * indent + 'DEBUG = os.environ.get("DEBUG", "false").lower() == "true"'

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Read DEBUG from environment variable",
            diff=f"- {line}\n+ {new_line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            manual_steps=["Add 'import os' if not already imported"],
            confidence="high",
            confidence_score=0.95,
        )

    def _fix_weak_hashing(self, finding: Finding, source: str) -> FixProposal | None:
        """SEC-009: Replace MD5/SHA1 with SHA256."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]
        new_line = line.replace("hashlib.md5", "hashlib.sha256")
        new_line = new_line.replace("hashlib.sha1", "hashlib.sha256")
        new_line = new_line.replace('hashlib.new("md5")', "hashlib.sha256()")
        new_line = new_line.replace("hashlib.new('md5')", "hashlib.sha256()")
        new_line = new_line.replace('hashlib.new("sha1")', "hashlib.sha256()")
        new_line = new_line.replace("hashlib.new('sha1')", "hashlib.sha256()")

        if new_line == line:
            return None

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Upgrade to SHA-256 hashing",
            diff=f"- {line}\n+ {new_line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            confidence="high",
            confidence_score=0.90,
        )

    def _fix_subprocess_shell(self, finding: Finding, source: str) -> FixProposal | None:
        """SEC-012: Replace shell=True with shell=False."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        if "shell=True" in line:
            new_line = line.replace("shell=True", "shell=False")
            return FixProposal(
                finding_id=finding.check_id,
                fix_type="rule_based",
                description="Disable shell execution in subprocess call",
                diff=f"- {line}\n+ {new_line}",
                file=finding.file,
                line_start=finding.line,
                line_end=finding.line,
                new_code=new_line,
                original_code=line,
                manual_steps=["Convert command string to argument list: ['cmd', 'arg1', 'arg2']"],
                confidence="high",
                confidence_score=0.85,
                confidence_reason="Shell=False is safer; ensure command is passed as list",
                side_effects=["Command string must be converted to argument list"],
            )

        if "os.system(" in line:
            new_line = line.replace("os.system(", "subprocess.run(")
            return FixProposal(
                finding_id=finding.check_id,
                fix_type="rule_based",
                description="Replace os.system() with subprocess.run()",
                diff=f"- {line}\n+ {new_line}",
                file=finding.file,
                line_start=finding.line,
                line_end=finding.line,
                new_code=new_line,
                original_code=line,
                manual_steps=["Convert command to list form and add shell=False"],
                confidence="medium",
                confidence_score=0.70,
            )

        return None

    def _fix_bare_except(self, finding: Finding, source: str) -> FixProposal | None:
        """ERR-001: Replace bare except with except Exception as e."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]
        new_line = re.sub(r'except\s*:', 'except Exception as e:', line)

        if new_line == line:
            return None

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Specify Exception type in except clause",
            diff=f"- {line}\n+ {new_line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            confidence="high",
            confidence_score=0.95,
        )

    def _fix_silent_except(self, finding: Finding, source: str) -> FixProposal | None:
        """ERR-002: Replace except: pass with logging."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]
        indent = len(line) - len(line.lstrip())

        # Fix the except line
        new_except = re.sub(r'except\s*:', 'except Exception as e:', line)
        if new_except == line and "except " in line:
            new_except = line  # Already typed, keep it

        # Check if next line is pass
        if finding.line < len(lines):
            next_line = lines[finding.line]
            if next_line.strip() == "pass" or next_line.strip() == "...":
                body_indent = len(next_line) - len(next_line.lstrip())
                new_body = " " * body_indent + "logger.exception(e)"

                return FixProposal(
                    finding_id=finding.check_id,
                    fix_type="rule_based",
                    description="Log exception instead of silencing",
                    diff=f"- {line}\n- {next_line}\n+ {new_except}\n+ {new_body}",
                    file=finding.file,
                    line_start=finding.line,
                    line_end=finding.line + 1,
                    new_code=f"{new_except}\n{new_body}",
                    original_code=f"{line}\n{next_line}",
                    manual_steps=["Add 'import logging; logger = logging.getLogger(__name__)' at top of file"],
                    confidence="high",
                    confidence_score=0.90,
                )

        return None

    def _fix_http_no_timeout(self, finding: Finding, source: str) -> FixProposal | None:
        """ERR-007: Add timeout=30 to HTTP calls."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        # Add timeout=30 before closing parenthesis
        if line.rstrip().endswith(")"):
            new_line = line.rstrip()[:-1] + ", timeout=30)"
        else:
            new_line = line.rstrip() + "  # TODO: add timeout=30"

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Add timeout=30 to HTTP call",
            diff=f"- {line}\n+ {new_line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            confidence="high",
            confidence_score=0.90,
        )

    def _fix_return_none_on_error(self, finding: Finding, source: str) -> FixProposal | None:
        """ERR-008: Replace return None with raise."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]
        indent = len(line) - len(line.lstrip())
        new_line = " " * indent + "raise"

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Re-raise exception instead of returning None",
            diff=f"- {line}\n+ {new_line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=new_line,
            original_code=line,
            confidence="high",
            confidence_score=0.85,
            confidence_reason="Re-raising preserves the original error for the caller",
        )

    def _fix_unused_import(self, finding: Finding, source: str) -> FixProposal | None:
        """CQ-004: Remove unused import line."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description=f"Remove unused import",
            diff=f"- {line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code="",
            original_code=line,
            confidence="high",
            confidence_score=0.90,
        )

    def _fix_star_import(self, finding: Finding, source: str) -> FixProposal | None:
        """CQ-009: Flag star import for replacement."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Replace star import with explicit imports",
            diff=f"- {line}\n+ # TODO: Replace with explicit imports",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code=line,  # Don't auto-fix star imports (need analysis)
            original_code=line,
            manual_steps=["Determine which names are actually used and import them explicitly"],
            confidence="medium",
            confidence_score=0.60,
            requires_review=True,
        )

    def _fix_dead_code(self, finding: Finding, source: str) -> FixProposal | None:
        """CQ-010: Remove unreachable code."""
        if not finding.file or not finding.line:
            return None

        lines = source.splitlines()
        if finding.line > len(lines):
            return None

        line = lines[finding.line - 1]

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="rule_based",
            description="Remove unreachable code",
            diff=f"- {line}",
            file=finding.file,
            line_start=finding.line,
            line_end=finding.line,
            new_code="",
            original_code=line,
            confidence="high",
            confidence_score=0.85,
        )
