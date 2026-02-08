"""Tests for code quality checks CQ-001 through CQ-010."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from devnog.scanner.checks.code_quality import (
    CQ001FunctionLength,
    CQ002DeepNesting,
    CQ003DuplicateCode,
    CQ004UnusedImports,
    CQ005MissingTypeHints,
    CQ006MissingDocstrings,
    CQ007HighComplexity,
    CQ008GlobalMutableState,
    CQ009StarImports,
    CQ010DeadCode,
)
from devnog.core.models import Category, Finding, Severity


FAKE_PATH = Path("test_file.py")


def _run_check(check, source: str) -> list[Finding]:
    """Helper: parse source and run a check."""
    tree = ast.parse(textwrap.dedent(source))
    return check.run(FAKE_PATH, textwrap.dedent(source), tree)


# ---------------------------------------------------------------------------
# CQ-001: Function too long
# ---------------------------------------------------------------------------
class TestCQ001FunctionLength:
    def test_detects_long_function(self):
        """A function over 50 lines should trigger CQ-001."""
        # Build a function body with 55 lines
        body_lines = "\n".join(f"    x_{i} = {i}" for i in range(53))
        source = f"def long_func():\n{body_lines}\n    return x_0\n"
        check = CQ001FunctionLength(max_length=50)
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-001"
        assert "long_func" in findings[0].message

    def test_clean_code(self):
        """A short function should not trigger CQ-001."""
        source = """\
def short_func():
    x = 1
    y = 2
    return x + y
"""
        check = CQ001FunctionLength(max_length=50)
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_custom_max_length(self):
        """Custom max_length should be respected."""
        body_lines = "\n".join(f"    x_{i} = {i}" for i in range(8))
        source = f"def medium_func():\n{body_lines}\n    return x_0\n"
        check = CQ001FunctionLength(max_length=5)
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_async_function(self):
        """Async functions should also be checked."""
        body_lines = "\n".join(f"    x_{i} = {i}" for i in range(53))
        source = f"async def long_async():\n{body_lines}\n    return x_0\n"
        check = CQ001FunctionLength(max_length=50)
        findings = _run_check(check, source)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# CQ-002: Deep nesting
# ---------------------------------------------------------------------------
class TestCQ002DeepNesting:
    def test_detects_deep_nesting(self):
        """Code nested >4 levels should trigger CQ-002."""
        source = """\
def deeply_nested():
    if True:
        for i in range(10):
            while True:
                if True:
                    with open("f") as f:
                        pass
"""
        check = CQ002DeepNesting(max_depth=4)
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-002"

    def test_clean_code(self):
        """Shallow nesting should not trigger CQ-002."""
        source = """\
def shallow():
    if True:
        for i in range(10):
            print(i)
"""
        check = CQ002DeepNesting(max_depth=4)
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_custom_max_depth(self):
        """Custom max_depth should be respected."""
        source = """\
def func():
    if True:
        if True:
            pass
"""
        check = CQ002DeepNesting(max_depth=1)
        findings = _run_check(check, source)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# CQ-003: Duplicate code
# ---------------------------------------------------------------------------
class TestCQ003DuplicateCode:
    def test_detects_duplicate_functions(self):
        """Two functions with identical bodies should trigger CQ-003."""
        body_lines = "\n".join(f"    x_{i} = {i}" for i in range(8))
        source = (
            f"def func_a():\n{body_lines}\n    return x_0\n\n"
            f"def func_b():\n{body_lines}\n    return x_0\n"
        )
        check = CQ003DuplicateCode(min_lines=6)
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-003"

    def test_clean_code(self):
        """Different function bodies should not trigger CQ-003."""
        source = """\
def func_a():
    x = 1
    y = 2
    z = 3
    w = 4
    v = 5
    return x + y + z

def func_b():
    a = 10
    b = 20
    c = 30
    d = 40
    e = 50
    return a * b * c
"""
        check = CQ003DuplicateCode(min_lines=6)
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CQ-004: Unused imports
# ---------------------------------------------------------------------------
class TestCQ004UnusedImports:
    def test_detects_unused_import(self):
        """An import that is never used should trigger CQ-004."""
        source = """\
import os
import sys

def func():
    return os.getcwd()
"""
        check = CQ004UnusedImports()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert any("sys" in f.message for f in findings)

    def test_clean_code(self):
        """All imports used should not trigger CQ-004."""
        source = """\
import os
import sys

def func():
    print(os.getcwd())
    print(sys.version)
"""
        check = CQ004UnusedImports()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_from_import_unused(self):
        """Unused from-import should be detected."""
        source = """\
from os.path import join, exists

def func():
    return join("a", "b")
"""
        check = CQ004UnusedImports()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert any("exists" in f.message for f in findings)

    def test_aliased_import_used(self):
        """An aliased import that is used should not trigger."""
        source = """\
import numpy as np

def func():
    return np.array([1, 2, 3])
"""
        check = CQ004UnusedImports()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CQ-005: Missing type hints
# ---------------------------------------------------------------------------
class TestCQ005MissingTypeHints:
    def test_detects_missing_type_hints(self):
        """A public function without type hints should trigger CQ-005."""
        source = """\
def greet(name):
    return f"Hello, {name}"
"""
        check = CQ005MissingTypeHints()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-005"
        assert "greet" in findings[0].message

    def test_clean_code(self):
        """A fully typed function should not trigger CQ-005."""
        source = """\
def greet(name: str) -> str:
    return f"Hello, {name}"
"""
        check = CQ005MissingTypeHints()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_private_function_skipped(self):
        """Private functions (starting with _) should be skipped."""
        source = """\
def _helper(x):
    return x * 2
"""
        check = CQ005MissingTypeHints()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_self_param_skipped(self):
        """self and cls params should not require type hints."""
        source = """\
class MyClass:
    def method(self, x: int) -> int:
        return x
"""
        check = CQ005MissingTypeHints()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CQ-006: Missing docstrings
# ---------------------------------------------------------------------------
class TestCQ006MissingDocstrings:
    def test_detects_missing_function_docstring(self):
        """A public function without a docstring should trigger CQ-006."""
        source = """\
def compute(x, y):
    return x + y
"""
        check = CQ006MissingDocstrings()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert "compute" in findings[0].message

    def test_clean_code(self):
        """A function with a docstring should not trigger CQ-006."""
        source = '''\
def compute(x, y):
    """Compute the sum of x and y."""
    return x + y
'''
        check = CQ006MissingDocstrings()
        findings = _run_check(check, source)
        # Only function findings, not class ones
        func_findings = [f for f in findings if "compute" in f.message]
        assert len(func_findings) == 0

    def test_class_missing_docstring(self):
        """A public class without a docstring should trigger CQ-006."""
        source = """\
class MyClass:
    pass
"""
        check = CQ006MissingDocstrings()
        findings = _run_check(check, source)
        assert any("MyClass" in f.message for f in findings)

    def test_private_function_skipped(self):
        """Private functions should not require docstrings."""
        source = """\
def _internal():
    return 42
"""
        check = CQ006MissingDocstrings()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CQ-007: High cyclomatic complexity
# ---------------------------------------------------------------------------
class TestCQ007HighComplexity:
    def test_detects_high_complexity(self):
        """A function with many branches should trigger CQ-007."""
        branches = "\n".join(
            f"    if x == {i}:\n        return {i}" for i in range(15)
        )
        source = f"def complex_func(x):\n{branches}\n"
        check = CQ007HighComplexity(max_complexity=10)
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-007"

    def test_clean_code(self):
        """A simple function should not trigger CQ-007."""
        source = """\
def simple(x):
    if x > 0:
        return x
    return -x
"""
        check = CQ007HighComplexity(max_complexity=10)
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_custom_max_complexity(self):
        """Custom max_complexity threshold should be respected."""
        source = """\
def func(x):
    if x > 0:
        if x > 10:
            return x
    return 0
"""
        check = CQ007HighComplexity(max_complexity=1)
        findings = _run_check(check, source)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# CQ-008: Global mutable state
# ---------------------------------------------------------------------------
class TestCQ008GlobalMutableState:
    def test_detects_global_mutable_list(self):
        """A global mutable list should trigger CQ-008."""
        source = """\
cache = []
"""
        check = CQ008GlobalMutableState()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-008"

    def test_detects_global_mutable_dict(self):
        """A global mutable dict should trigger CQ-008."""
        source = """\
registry = {}
"""
        check = CQ008GlobalMutableState()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code_constant(self):
        """UPPERCASE constants should not trigger CQ-008."""
        source = """\
MAX_RETRIES = 3
CACHE = []
"""
        check = CQ008GlobalMutableState()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_clean_code_immutable(self):
        """Immutable global assignments should not trigger CQ-008."""
        source = """\
name = "hello"
count = 42
"""
        check = CQ008GlobalMutableState()
        findings = _run_check(check, source)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CQ-009: Star imports
# ---------------------------------------------------------------------------
class TestCQ009StarImports:
    def test_detects_star_import(self):
        """from X import * should trigger CQ-009."""
        source = """\
from os.path import *
"""
        check = CQ009StarImports()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-009"
        assert "os.path" in findings[0].message

    def test_clean_code(self):
        """Explicit imports should not trigger CQ-009."""
        source = """\
from os.path import join, exists
import os
"""
        check = CQ009StarImports()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_multiple_star_imports(self):
        """Multiple star imports should each be detected."""
        source = """\
from os.path import *
from sys import *
"""
        check = CQ009StarImports()
        findings = _run_check(check, source)
        assert len(findings) >= 2


# ---------------------------------------------------------------------------
# CQ-010: Dead code
# ---------------------------------------------------------------------------
class TestCQ010DeadCode:
    def test_detects_code_after_return(self):
        """Code after return should trigger CQ-010."""
        source = """\
def func():
    return 42
    print("unreachable")
"""
        check = CQ010DeadCode()
        findings = _run_check(check, source)
        assert len(findings) >= 1
        assert findings[0].check_id == "CQ-010"
        assert "return" in findings[0].message.lower()

    def test_detects_code_after_raise(self):
        """Code after raise should trigger CQ-010."""
        source = """\
def func():
    raise ValueError("boom")
    return 0
"""
        check = CQ010DeadCode()
        findings = _run_check(check, source)
        assert len(findings) >= 1

    def test_clean_code(self):
        """Functions with reachable code should not trigger CQ-010."""
        source = """\
def func(x):
    if x > 0:
        return x
    return -x
"""
        check = CQ010DeadCode()
        findings = _run_check(check, source)
        assert len(findings) == 0

    def test_detects_code_after_break(self):
        """Code after break in a loop should trigger CQ-010."""
        source = """\
def func():
    for i in range(10):
        break
        print("unreachable")
"""
        check = CQ010DeadCode()
        findings = _run_check(check, source)
        assert len(findings) >= 1
