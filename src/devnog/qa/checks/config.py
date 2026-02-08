"""QA checks for production configuration safety (QA-014 through QA-016)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck


class QA014HardcodedSecrets(QACheck):
    """Detect secrets or credentials hardcoded in source files.

    Secrets committed to source control will appear in build artefacts,
    container images, and version history — making rotation painful and
    leaks likely.
    """

    check_id = "QA-014"
    category = Category.PROD_READINESS
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "Hardcoded secret or credential in source code"
    required = True

    _SECRET_VAR_PATTERNS = re.compile(
        r"(?i)(password|passwd|secret|api_key|apikey|token|auth_token|"
        r"access_key|private_key|client_secret|db_pass|database_password|"
        r"jwt_secret|encryption_key|signing_key)",
    )
    _SAFE_VALUES = frozenset({
        "", "None", "none", "null", "changeme", "CHANGEME",
        "xxx", "XXX", "your-secret-here", "TODO", "test",
        "password", "secret",  # obvious placeholder names
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            # Skip test files — they commonly use dummy secrets.
            if self._is_test_file(file_path):
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    self._check_assignment(node, file_path, findings)
                elif isinstance(node, ast.AnnAssign) and node.value:
                    self._check_ann_assignment(node, file_path, findings)

        return findings

    # ------------------------------------------------------------------

    def _check_assignment(
        self,
        node: ast.Assign,
        file_path: Path,
        findings: list[Finding],
    ) -> None:
        for target in node.targets:
            var_name = self._target_name(target)
            if not var_name:
                continue
            if not self._SECRET_VAR_PATTERNS.search(var_name):
                continue
            if self._value_is_env_lookup(node.value):
                continue
            if self._value_is_safe(node.value):
                continue

            findings.append(self._make_finding(
                message=f"Hardcoded value assigned to secret variable '{var_name}'",
                file_path=file_path,
                line=node.lineno,
                suggestion=(
                    f"Use os.environ['{var_name.upper()}'] or a secrets "
                    "manager instead of hardcoding"
                ),
            ))

    def _check_ann_assignment(
        self,
        node: ast.AnnAssign,
        file_path: Path,
        findings: list[Finding],
    ) -> None:
        var_name = self._target_name(node.target)
        if not var_name:
            return
        if not self._SECRET_VAR_PATTERNS.search(var_name):
            return
        if node.value and self._value_is_env_lookup(node.value):
            return
        if node.value and self._value_is_safe(node.value):
            return

        findings.append(self._make_finding(
            message=f"Hardcoded value assigned to secret variable '{var_name}'",
            file_path=file_path,
            line=node.lineno,
            suggestion=(
                f"Use os.environ['{var_name.upper()}'] or a secrets "
                "manager instead of hardcoding"
            ),
        ))

    # ------------------------------------------------------------------

    @staticmethod
    def _target_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _value_is_env_lookup(value: ast.expr) -> bool:
        """Return True if the value comes from os.environ or similar."""
        if isinstance(value, ast.Call):
            dump = ast.dump(value)
            if any(m in dump for m in ("environ", "getenv", "config", "settings", "Secret")):
                return True
        if isinstance(value, ast.Subscript):
            dump = ast.dump(value)
            if "environ" in dump:
                return True
        return False

    def _value_is_safe(self, value: ast.expr) -> bool:
        if isinstance(value, ast.Constant):
            s = str(value.value).strip()
            if s in self._SAFE_VALUES:
                return True
            # Very short strings are likely placeholders.
            if isinstance(value.value, str) and len(value.value) <= 2:
                return True
        if isinstance(value, ast.NameConstant):  # Python 3.7 compat
            return True
        if isinstance(value, ast.Constant) and value.value is None:
            return True
        return False

    @staticmethod
    def _is_test_file(path: Path) -> bool:
        parts = path.parts
        return (
            "test" in path.name.lower()
            or "tests" in parts
            or "test" in parts
            or "conftest" in path.name
        )


class QA015DebugModeEnabled(QACheck):
    """Detect debug mode left enabled in production configuration.

    Running with DEBUG=True in production exposes stack traces, internal
    state, and often disables critical security features.
    """

    check_id = "QA-015"
    category = Category.PROD_READINESS
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "Debug mode appears enabled in production config"
    required = True

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            # Skip test/dev specific config files.
            name_lower = file_path.name.lower()
            if any(t in name_lower for t in ("test", "dev", "local", "example")):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue

                for target in node.targets:
                    var_name = ""
                    if isinstance(target, ast.Name):
                        var_name = target.id
                    elif isinstance(target, ast.Attribute):
                        var_name = target.attr

                    if var_name.upper() != "DEBUG":
                        continue

                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        findings.append(self._make_finding(
                            message=(
                                f"DEBUG = True in '{file_path.name}' — "
                                "must be False in production"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            suggestion=(
                                "Set DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true' "
                                "or remove the hardcoded True"
                            ),
                        ))

        return findings


class QA016MissingEnvValidation(QACheck):
    """Detect required environment variables read without validation.

    Missing environment variables in production cause confusing
    ``KeyError`` or ``None`` propagation instead of a clear startup failure.
    """

    check_id = "QA-016"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Environment variable read without validation"

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
                if not self._is_getenv(node):
                    continue

                # os.getenv("VAR") returns None by default — no validation.
                # os.environ["VAR"] raises KeyError — that *is* validation.
                # os.environ.get("VAR") also returns None.
                if len(node.args) >= 1 and len(node.args) < 2:
                    # No default provided
                    if not self._has_surrounding_validation(node, tree):
                        var_name = ""
                        if isinstance(node.args[0], ast.Constant):
                            var_name = str(node.args[0].value)
                        findings.append(self._make_finding(
                            message=(
                                f"os.getenv('{var_name}') called without "
                                "default or validation — may silently be None"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            suggestion=(
                                "Use os.environ['VAR'] to fail fast, or "
                                "provide a sensible default, or validate "
                                "at startup."
                            ),
                        ))

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _is_getenv(node: ast.Call) -> bool:
        # os.getenv(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "getenv":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                return True
        # os.environ.get(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if isinstance(node.func.value, ast.Attribute):
                if (
                    node.func.value.attr == "environ"
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "os"
                ):
                    return True
        return False

    @staticmethod
    def _has_surrounding_validation(node: ast.Call, tree: ast.Module) -> bool:
        """Heuristic: check if the result is immediately asserted or checked."""
        # Walk parent assignments — if the result feeds into ``or`` / ``if``
        # / ``assert``, consider it validated.
        for parent in ast.walk(tree):
            if isinstance(parent, ast.Assert):
                if hasattr(parent, "lineno") and parent.lineno == node.lineno:
                    return True
            if isinstance(parent, ast.If):
                if hasattr(parent, "lineno") and parent.lineno == node.lineno:
                    return True
            if isinstance(parent, ast.BoolOp):
                # pattern: VAR = os.getenv("X") or raise_error()
                if hasattr(parent, "lineno") and parent.lineno == node.lineno:
                    return True
        return False
