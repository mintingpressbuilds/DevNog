"""QA checks for data safety in production (QA-012 through QA-013)."""

from __future__ import annotations

import ast
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.qa.checks.base import QACheck


class QA012SQLWithoutParameterization(QACheck):
    """Detect SQL queries built via string formatting instead of parameters.

    Un-parameterized queries are the leading cause of SQL injection in
    production and also prevent the database from re-using query plans.
    """

    check_id = "QA-012"
    category = Category.PROD_READINESS
    severity = Severity.CRITICAL
    fix_type = FixType.AI_GENERATED
    description = "SQL query uses string formatting instead of parameterized queries"
    required = True

    _SQL_KEYWORDS = frozenset({
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
        "CREATE", "ALTER", "TRUNCATE", "MERGE",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            for node in ast.walk(tree):
                # --- f-strings containing SQL ----
                if isinstance(node, ast.JoinedStr):
                    literal_parts = self._fstring_literal_parts(node)
                    if self._looks_like_sql(literal_parts):
                        findings.append(self._make_finding(
                            message=(
                                "SQL query built with f-string — "
                                "use parameterized queries instead"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            suggestion=(
                                "Replace with cursor.execute(sql, params) "
                                "using %s or :name placeholders"
                            ),
                        ))

                # --- %-formatting: "SELECT ... %s" % var ----
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    if isinstance(node.left, ast.Constant) and isinstance(
                        node.left.value, str
                    ):
                        if self._looks_like_sql(node.left.value):
                            findings.append(self._make_finding(
                                message=(
                                    "SQL query built with %-formatting — "
                                    "use parameterized queries instead"
                                ),
                                file_path=file_path,
                                line=node.lineno,
                                suggestion=(
                                    "Replace with cursor.execute(sql, params)"
                                ),
                            ))

                # --- .format() on SQL strings ----
                if isinstance(node, ast.Call) and isinstance(
                    node.func, ast.Attribute
                ):
                    if node.func.attr == "format":
                        val = node.func.value
                        if isinstance(val, ast.Constant) and isinstance(
                            val.value, str
                        ):
                            if self._looks_like_sql(val.value):
                                findings.append(self._make_finding(
                                    message=(
                                        "SQL query built with .format() — "
                                        "use parameterized queries instead"
                                    ),
                                    file_path=file_path,
                                    line=node.lineno,
                                    suggestion=(
                                        "Replace with cursor.execute(sql, params)"
                                    ),
                                ))

                # --- string concatenation with SQL ----
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    if isinstance(node.left, ast.Constant) and isinstance(
                        node.left.value, str
                    ):
                        if self._looks_like_sql(node.left.value):
                            findings.append(self._make_finding(
                                message=(
                                    "SQL query built with string concatenation — "
                                    "use parameterized queries instead"
                                ),
                                file_path=file_path,
                                line=node.lineno,
                                suggestion=(
                                    "Replace with cursor.execute(sql, params)"
                                ),
                            ))

        return findings

    # ------------------------------------------------------------------

    def _looks_like_sql(self, text: str) -> bool:
        upper = text.upper().strip()
        return any(upper.startswith(kw) for kw in self._SQL_KEYWORDS)

    @staticmethod
    def _fstring_literal_parts(node: ast.JoinedStr) -> str:
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return " ".join(parts)


class QA013MissingTransactionHandling(QACheck):
    """Detect database write operations outside explicit transactions.

    Without explicit transaction boundaries, partial writes can leave the
    database in an inconsistent state on failure.
    """

    check_id = "QA-013"
    category = Category.PROD_READINESS
    severity = Severity.WARNING
    fix_type = FixType.AI_GENERATED
    description = "Database writes without explicit transaction handling"

    _WRITE_METHODS = frozenset({
        "execute", "executemany", "executescript",
        "bulk_insert", "bulk_update", "bulk_create",
        "save", "add", "add_all", "merge", "delete",
    })
    _TRANSACTION_MARKERS = frozenset({
        "commit", "begin", "transaction", "atomic",
        "begin_nested", "session_scope",
    })

    def run(
        self,
        project_path: Path,
        source_files: list[tuple[Path, str, ast.Module]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for file_path, source, tree in source_files:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                write_calls: list[ast.Call] = []
                has_transaction = False

                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        name = self._attr_name(child)
                        if name in self._WRITE_METHODS:
                            write_calls.append(child)
                        if name in self._TRANSACTION_MARKERS:
                            has_transaction = True

                    # with session.begin(): / with atomic(): patterns
                    if isinstance(child, (ast.With, ast.AsyncWith)):
                        for item in child.items:
                            ctx = item.context_expr
                            if isinstance(ctx, ast.Call):
                                ctx_name = self._attr_name(ctx)
                                if ctx_name in self._TRANSACTION_MARKERS:
                                    has_transaction = True
                            if isinstance(ctx, ast.Attribute):
                                if ctx.attr in self._TRANSACTION_MARKERS:
                                    has_transaction = True

                # Check for decorator-based transaction (e.g. @atomic)
                for deco in node.decorator_list:
                    deco_src = ast.dump(deco)
                    if any(m in deco_src for m in ("atomic", "transaction", "transactional")):
                        has_transaction = True

                if write_calls and not has_transaction:
                    first = write_calls[0]
                    findings.append(self._make_finding(
                        message=(
                            f"Function '{node.name}()' performs database writes "
                            "without explicit transaction handling"
                        ),
                        file_path=file_path,
                        line=first.lineno,
                        suggestion=(
                            "Wrap writes in an explicit transaction "
                            "(e.g. with session.begin(): or @atomic)"
                        ),
                    ))

        return findings

    @staticmethod
    def _attr_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""
