"""Security checks (SEC-001 through SEC-012)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.scanner.checks.base import BaseCheck

# Patterns that suggest a value is a secret
SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token)",
    r"(?i)(password|passwd|pwd)",
    r"(?i)(private[_-]?key|secret)",
    r"(?i)(database[_-]?url|db[_-]?password)",
    r"(?i)(aws[_-]?secret|stripe[_-]?key|sendgrid)",
    r"sk-[a-zA-Z0-9]{20,}",  # OpenAI-style keys
    r"ghp_[a-zA-Z0-9]{36}",  # GitHub PATs
    r"AKIA[0-9A-Z]{16}",     # AWS access keys
]

def _get_decorator_name(node: ast.AST) -> str | None:
    """Extract the name of a decorator from its AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return None


SECRET_VAR_NAMES = {
    "api_key", "apikey", "api_secret", "secret_key", "secret",
    "password", "passwd", "pwd", "token", "auth_token",
    "access_token", "refresh_token", "private_key",
    "database_url", "db_password", "db_pass",
    "aws_secret_access_key", "aws_access_key_id",
    "stripe_secret_key", "stripe_key",
    "sendgrid_api_key", "openai_api_key",
}


class SEC001HardcodedSecrets(BaseCheck):
    """Detect hardcoded secrets/API keys."""

    check_id = "SEC-001"
    category = Category.SECURITY
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "Hardcoded secret"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if var_name in SECRET_VAR_NAMES or any(
                            re.search(p, target.id, re.IGNORECASE) for p in SECRET_PATTERNS[:5]
                        ):
                            if isinstance(node.value, ast.Constant) and isinstance(
                                node.value.value, str
                            ):
                                val = node.value.value
                                if len(val) > 3 and val not in ("", "None", "null", "TODO"):
                                    findings.append(self._make_finding(
                                        message=f"Hardcoded secret in '{target.id}'",
                                        file_path=file_path,
                                        line=node.lineno,
                                        suggestion=f'Replace with os.environ["{target.id.upper()}"]',
                                    ))

            # Also check for secret-like string values in variable assignments
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    val = node.value.value
                    for pattern in SECRET_PATTERNS[5:]:  # Check value patterns
                        if re.search(pattern, val):
                            line = node.lineno
                            findings.append(self._make_finding(
                                message="Hardcoded API key/token detected in string value",
                                file_path=file_path,
                                line=line,
                                suggestion="Move to environment variable",
                            ))
                            break

        return findings


class SEC002SQLInjection(BaseCheck):
    """Detect SQL injection vulnerabilities."""

    check_id = "SEC-002"
    category = Category.SECURITY
    severity = Severity.CRITICAL
    fix_type = FixType.AI_GENERATED
    description = "SQL injection risk"

    # Patterns that strongly indicate SQL: keyword followed by table-like context
    SQL_PATTERNS = [
        r"\bSELECT\b.+\bFROM\b",
        r"\bINSERT\b.+\bINTO\b",
        r"\bUPDATE\b.+\bSET\b",
        r"\bDELETE\b.+\bFROM\b",
        r"\bDROP\b\s+\b(?:TABLE|DATABASE|INDEX)\b",
        r"\bCREATE\b\s+\b(?:TABLE|DATABASE|INDEX)\b",
        r"\bALTER\b\s+\bTABLE\b",
    ]

    def _is_sql(self, text: str) -> bool:
        """Return True if *text* looks like a SQL query (not just a word match)."""
        import re
        upper = text.upper()
        return any(re.search(pat, upper) for pat in self.SQL_PATTERNS)

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            # f-string with SQL
            if isinstance(node, ast.JoinedStr):
                sql_text = self._extract_fstring_text(node)
                if self._is_sql(sql_text):
                    findings.append(self._make_finding(
                        message="SQL injection risk: f-string used in SQL query",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Use parameterized query instead of f-string",
                    ))

            # format() with SQL
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    if isinstance(node.func.value, ast.Constant) and isinstance(
                        node.func.value.value, str
                    ):
                        if self._is_sql(node.func.value.value):
                            findings.append(self._make_finding(
                                message="SQL injection risk: .format() used in SQL query",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Use parameterized query instead of .format()",
                            ))

            # % formatting with SQL
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if self._is_sql(node.left.value):
                        findings.append(self._make_finding(
                            message="SQL injection risk: % formatting used in SQL query",
                            file_path=file_path,
                            line=node.lineno,
                            suggestion="Use parameterized query instead of % formatting",
                        ))

        return findings

    def _extract_fstring_text(self, node: ast.JoinedStr) -> str:
        """Extract the literal text parts of an f-string."""
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
        return " ".join(parts)


class SEC003MissingRateLimiting(BaseCheck):
    """Detect missing rate limiting on routes."""

    check_id = "SEC-003"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "No rate limiting"

    ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_view"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        rate_limit_found = "rate_limit" in source.lower() or "throttle" in source.lower() or "ratelimit" in source.lower()

        if rate_limit_found:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = [_get_decorator_name(d) for d in node.decorator_list]
                if any(d in self.ROUTE_DECORATORS for d in decorators if d):
                    findings.append(self._make_finding(
                        message=f"No rate limiting on route '{node.name}'",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Add rate limiting middleware or decorator",
                    ))
                    break  # One finding per file is enough

        return findings


class SEC004DangerousEval(BaseCheck):
    """Detect eval(), exec(), and pickle.loads() usage."""

    check_id = "SEC-004"
    category = Category.SECURITY
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "Dangerous eval/exec usage"

    DANGEROUS_CALLS = {"eval", "exec"}
    DANGEROUS_ATTRS = {"loads"}  # pickle.loads

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in self.DANGEROUS_CALLS:
                    findings.append(self._make_finding(
                        message=f"Dangerous function: {node.func.id}() can execute arbitrary code",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=f"Replace {node.func.id}() with ast.literal_eval() if parsing literals",
                    ))
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr == "loads" and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "pickle":
                            findings.append(self._make_finding(
                                message="Dangerous function: pickle.loads() can execute arbitrary code",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Use json.loads() or a safe deserialization method",
                            ))
        return findings


class SEC005OpenCORS(BaseCheck):
    """Detect open CORS configuration."""

    check_id = "SEC-005"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Open CORS policy"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        # Check for allow_origins=["*"] or CORS(allow_all_origins=True)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in ("allow_origins", "origins"):
                        if isinstance(kw.value, ast.List):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and elt.value == "*":
                                    findings.append(self._make_finding(
                                        message="Open CORS: allow_origins=['*'] allows all domains",
                                        file_path=file_path,
                                        line=node.lineno,
                                        suggestion="Restrict CORS origins to specific domains",
                                    ))
                    elif kw.arg in ("allow_all_origins", "CORS_ALLOW_ALL_ORIGINS"):
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(self._make_finding(
                                message="Open CORS: all origins allowed",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Restrict CORS origins to specific domains",
                            ))

        # Also check for CORS_ALLOW_ALL_ORIGINS = True assignment
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and "CORS" in target.id.upper() and "ALL" in target.id.upper():
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            findings.append(self._make_finding(
                                message=f"Open CORS: {target.id} = True",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Restrict CORS origins to specific domains",
                            ))

        return findings


class SEC006DebugTrue(BaseCheck):
    """Detect DEBUG=True in config."""

    check_id = "SEC-006"
    category = Category.SECURITY
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "DEBUG=True in config"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            findings.append(self._make_finding(
                                message="DEBUG = True in production-accessible code",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion='Replace with os.environ.get("DEBUG", "false").lower() == "true"',
                            ))
        return findings


class SEC007JWTNoExpiry(BaseCheck):
    """Detect JWT creation without expiration."""

    check_id = "SEC-007"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "JWT without expiration"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and "encode" in func_name.lower():
                    # Check if this looks like a JWT encode call
                    is_jwt = False
                    if isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            if node.func.value.id.lower() in ("jwt", "jose", "pyjwt"):
                                is_jwt = True

                    if is_jwt:
                        # Check if payload includes 'exp'
                        has_exp = False
                        if node.args:
                            payload_arg = node.args[0]
                            if isinstance(payload_arg, ast.Dict):
                                for key in payload_arg.keys:
                                    if isinstance(key, ast.Constant) and key.value == "exp":
                                        has_exp = True

                        if not has_exp:
                            findings.append(self._make_finding(
                                message="JWT created without expiration (exp claim)",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Add 'exp' claim to JWT payload",
                            ))

        return findings

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


class SEC008TokensInURL(BaseCheck):
    """Detect tokens/secrets passed in URL parameters."""

    check_id = "SEC-008"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Token in URL parameter"

    SENSITIVE_PARAMS = {"token", "api_key", "apikey", "key", "secret", "password", "auth"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        # Check for URLs with sensitive params in f-strings or string concatenation
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comment lines and string literals used for documentation
            if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            for param in self.SENSITIVE_PARAMS:
                # Look for URL construction patterns with sensitive params
                patterns = [
                    f"?{param}=",
                    f"&{param}=",
                    f"params={{'{param}'",
                    f'params={{"{param}"',
                ]
                if any(p in line.lower() for p in patterns):
                    if "url" in line.lower() or "http" in line.lower() or "request" in line.lower():
                        findings.append(self._make_finding(
                            message=f"Sensitive parameter '{param}' in URL",
                            file_path=file_path,
                            line=i,
                            suggestion="Move sensitive data to headers (Authorization, X-API-Key)",
                        ))
                        break

        return findings


class SEC009WeakHashing(BaseCheck):
    """Detect weak hashing algorithms (MD5/SHA1)."""

    check_id = "SEC-009"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Weak hashing algorithm"

    WEAK_HASHES = {"md5", "sha1"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.WEAK_HASHES:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                            findings.append(self._make_finding(
                                message=f"Weak hash algorithm: hashlib.{node.func.attr}()",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion=f"Replace hashlib.{node.func.attr}() with hashlib.sha256()",
                            ))
                elif isinstance(node.func, ast.Name) and node.func.id in self.WEAK_HASHES:
                    findings.append(self._make_finding(
                        message=f"Weak hash algorithm: {node.func.id}()",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=f"Replace {node.func.id}() with hashlib.sha256()",
                    ))

            # Check for hashlib.new("md5") / hashlib.new("sha1")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                        if node.args and isinstance(node.args[0], ast.Constant):
                            if str(node.args[0].value).lower() in self.WEAK_HASHES:
                                findings.append(self._make_finding(
                                    message=f"Weak hash algorithm: hashlib.new('{node.args[0].value}')",
                                    file_path=file_path,
                                    line=node.lineno,
                                    suggestion="Use hashlib.sha256() instead",
                                ))

        return findings


class SEC010PathTraversal(BaseCheck):
    """Detect potential file path traversal vulnerabilities."""

    check_id = "SEC-010"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Path traversal risk"

    # Bare builtin calls (ast.Name)
    FILE_BUILTINS = {"open"}
    # Method calls on objects (ast.Attribute) — excludes 'open' to avoid
    # false positives like webbrowser.open()
    FILE_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []

        # Collect function parameter names to identify truly user-controlled paths
        func_params: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    func_params.add(arg.arg)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                is_file_op = False
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    is_file_op = func_name in self.FILE_BUILTINS
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    is_file_op = func_name in self.FILE_METHODS

                if is_file_op and node.args:
                    arg = node.args[0]
                    # Check if the path argument uses user input (f-string, format, +)
                    if isinstance(arg, ast.JoinedStr):
                        # Only flag if the f-string references a function parameter
                        if self._references_params(arg, func_params):
                            findings.append(self._make_finding(
                                message=f"Potential path traversal: user-controlled path in {func_name}()",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Sanitize path input: use Path.resolve() and validate prefix",
                            ))
                    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        if self._references_params(arg, func_params):
                            findings.append(self._make_finding(
                                message=f"Potential path traversal: concatenated path in {func_name}()",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Sanitize path input: use Path.resolve() and validate prefix",
                            ))
        return findings

    def _references_params(self, node: ast.AST, params: set[str]) -> bool:
        """Check if an AST node references any function parameters."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in params:
                return True
        return False


class SEC011MissingInputValidation(BaseCheck):
    """Detect missing input validation on route handlers."""

    check_id = "SEC-011"
    category = Category.SECURITY
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Missing input validation"

    ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_view"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        # Check if file has any validation-like imports
        has_validation = any(
            kw in source.lower()
            for kw in ("pydantic", "marshmallow", "validate", "schema", "serializer", "form")
        )
        if has_validation:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = [_get_decorator_name(d) for d in node.decorator_list]
                if any(d in self.ROUTE_DECORATORS for d in decorators if d):
                    # Check if function body accesses request data without validation
                    body_source = ast.dump(node)
                    if ("request" in body_source and
                            any(kw in body_source for kw in ("json", "form", "data", "body", "args"))):
                        findings.append(self._make_finding(
                            message=f"Route '{node.name}' may lack input validation",
                            file_path=file_path,
                            line=node.lineno,
                            suggestion="Add input validation (Pydantic, marshmallow, or manual checks)",
                        ))
        return findings


class SEC012SubprocessShell(BaseCheck):
    """Detect subprocess calls with shell=True."""

    check_id = "SEC-012"
    category = Category.SECURITY
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "subprocess with shell=True"

    SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                is_subprocess = False

                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        is_subprocess = node.func.value.id == "subprocess"
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in self.SUBPROCESS_CALLS and is_subprocess:
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                findings.append(self._make_finding(
                                    message=f"subprocess.{func_name}(shell=True) — command injection risk",
                                    file_path=file_path,
                                    line=node.lineno,
                                    suggestion="Rewrite with shell=False and pass arguments as a list",
                                ))

                # Also check os.system()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "system" and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "os":
                            findings.append(self._make_finding(
                                message="os.system() — command injection risk",
                                file_path=file_path,
                                line=node.lineno,
                                suggestion="Replace os.system() with subprocess.run(shell=False)",
                            ))
        return findings
