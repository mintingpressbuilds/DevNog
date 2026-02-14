"""Dependency checks (DEP-001 through DEP-008)."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

from devnog.core.models import Category, Finding, FixType, Severity
from devnog.scanner.checks.base import DependencyCheck


def _parse_requirements(project_path: Path) -> list[tuple[str, str, Path]]:
    """Parse requirements files and return list of (package, version_spec, file)."""
    deps: list[tuple[str, str, Path]] = []

    for req_file in ("requirements.txt", "requirements/base.txt", "requirements/prod.txt"):
        path = project_path / req_file
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Parse: package==1.0.0 or package>=1.0.0 or just package
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~]+.*)?$", line)
                if match:
                    deps.append((match.group(1), match.group(2) or "", path))

    # Also check pyproject.toml dependencies
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                tomllib = None  # type: ignore[assignment]

        if tomllib:
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                for dep in data.get("project", {}).get("dependencies", []):
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~]+.*)?$", dep.strip())
                    if match:
                        deps.append((match.group(1), match.group(2) or "", pyproject))
            except Exception:
                pass  # skip unparseable pyproject.toml

    return deps


def _get_installed_packages() -> dict[str, str]:
    """Get currently installed packages and their versions."""
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            import json
            packages = json.loads(result.stdout)
            return {p["name"].lower(): p["version"] for p in packages}
    except Exception:
        pass  # pip may not be available; return empty package list
    return {}


class DEP001KnownCVEs(DependencyCheck):
    """Check for dependencies with known CVEs."""

    check_id = "DEP-001"
    category = Category.DEPENDENCIES
    severity = Severity.CRITICAL
    fix_type = FixType.RULE_BASED
    description = "Dependency with known CVE"

    # Known vulnerable versions (simplified - real implementation would use a CVE database)
    KNOWN_VULNERABLE: dict[str, list[str]] = {
        "requests": ["<2.31.0"],
        "urllib3": ["<2.0.7"],
        "cryptography": ["<41.0.4"],
        "django": ["<4.2.7"],
        "flask": ["<2.3.3"],
        "pillow": ["<10.0.1"],
        "numpy": ["<1.22.0"],
        "pyyaml": ["<6.0.1"],
        "jinja2": ["<3.1.3"],
        "werkzeug": ["<3.0.1"],
    }

    def run(self, project_path: Path) -> list[Finding]:
        findings = []
        deps = _parse_requirements(project_path)
        installed = _get_installed_packages()

        for pkg_name, version_spec, req_file in deps:
            pkg_lower = pkg_name.lower()
            if pkg_lower in self.KNOWN_VULNERABLE:
                installed_version = installed.get(pkg_lower)
                if not installed_version:
                    continue
                # Check if the installed version falls within a vulnerable range
                for constraint in self.KNOWN_VULNERABLE[pkg_lower]:
                    if self._version_matches(installed_version, constraint):
                        findings.append(self._make_finding(
                            message=f"Package '{pkg_name}' ({installed_version}) has known vulnerabilities (affected: {constraint})",
                            file_path=req_file,
                            suggestion=f"Run: pip install --upgrade {pkg_name}",
                            severity=Severity.CRITICAL,
                            fix_type=FixType.RULE_BASED,
                        ))

        return findings

    @staticmethod
    def _version_matches(installed: str, constraint: str) -> bool:
        """Check if an installed version matches a vulnerability constraint like '<41.0.4'."""
        match = re.match(r"([<>=!]+)\s*([\d.]+)", constraint)
        if not match:
            return False
        op, threshold = match.group(1), match.group(2)
        try:
            inst_parts = [int(x) for x in installed.split(".")[:3]]
            thresh_parts = [int(x) for x in threshold.split(".")[:3]]
            # Pad to equal length
            while len(inst_parts) < len(thresh_parts):
                inst_parts.append(0)
            while len(thresh_parts) < len(inst_parts):
                thresh_parts.append(0)
        except ValueError:
            return False
        if op == "<":
            return inst_parts < thresh_parts
        if op == "<=":
            return inst_parts <= thresh_parts
        if op == "==":
            return inst_parts == thresh_parts
        return False


class DEP002AbandonedPackages(DependencyCheck):
    """Check for abandoned packages (no updates in >12 months)."""

    check_id = "DEP-002"
    category = Category.DEPENDENCIES
    severity = Severity.INFO
    fix_type = FixType.MANUAL
    description = "Potentially abandoned package"

    # Packages known to be unmaintained (simplified list)
    KNOWN_ABANDONED = {
        "nose", "pycrypto", "optparse", "imp",
    }

    def run(self, project_path: Path) -> list[Finding]:
        findings = []
        deps = _parse_requirements(project_path)

        for pkg_name, _, req_file in deps:
            if pkg_name.lower() in self.KNOWN_ABANDONED:
                findings.append(self._make_finding(
                    message=f"Package '{pkg_name}' appears abandoned/unmaintained",
                    file_path=req_file,
                    suggestion=f"Consider replacing '{pkg_name}' with an actively maintained alternative",
                ))

        return findings


class DEP003UnpinnedDeps(DependencyCheck):
    """Check for unpinned dependencies."""

    check_id = "DEP-003"
    category = Category.DEPENDENCIES
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Unpinned dependency"

    def run(self, project_path: Path) -> list[Finding]:
        findings = []
        deps = _parse_requirements(project_path)

        for pkg_name, version_spec, req_file in deps:
            if not version_spec or version_spec.strip() == "":
                findings.append(self._make_finding(
                    message=f"Unpinned dependency: '{pkg_name}' — version not specified",
                    file_path=req_file,
                    suggestion=f"Pin version: {pkg_name}==<current_version>",
                    fix_type=FixType.RULE_BASED,
                ))

        return findings


class DEP004UnusedDeps(DependencyCheck):
    """Check for unused dependencies."""

    check_id = "DEP-004"
    category = Category.DEPENDENCIES
    severity = Severity.INFO
    fix_type = FixType.RULE_BASED
    description = "Unused dependency"

    def run(self, project_path: Path) -> list[Finding]:
        findings = []
        deps = _parse_requirements(project_path)

        if not deps:
            return findings

        # Collect all imports from Python files
        imported_modules: set[str] = set()
        for py_file in project_path.rglob("*.py"):
            # Skip venv and other excluded dirs
            parts = py_file.parts
            if any(p in (".venv", "venv", "node_modules", ".git", "__pycache__") for p in parts):
                continue
            try:
                source = py_file.read_text(errors="ignore")
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imported_modules.add(alias.name.split(".")[0].lower())
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imported_modules.add(node.module.split(".")[0].lower())
            except (SyntaxError, UnicodeDecodeError):
                continue

        # Package name to import name mapping (common differences)
        PKG_TO_IMPORT = {
            "pillow": "pil",
            "scikit-learn": "sklearn",
            "python-dateutil": "dateutil",
            "pyyaml": "yaml",
            "python-dotenv": "dotenv",
            "beautifulsoup4": "bs4",
        }

        for pkg_name, _, req_file in deps:
            import_name = PKG_TO_IMPORT.get(pkg_name.lower(), pkg_name.lower().replace("-", "_"))
            if import_name not in imported_modules:
                findings.append(self._make_finding(
                    message=f"Possibly unused dependency: '{pkg_name}'",
                    file_path=req_file,
                    suggestion=f"Remove '{pkg_name}' from requirements if not needed",
                    fix_type=FixType.RULE_BASED,
                ))

        return findings


class DEP005DuplicateFunctionality(DependencyCheck):
    """Check for packages with duplicate functionality."""

    check_id = "DEP-005"
    category = Category.DEPENDENCIES
    severity = Severity.INFO
    fix_type = FixType.MANUAL
    description = "Duplicate functionality packages"

    DUPLICATE_GROUPS = [
        {"requests", "httpx", "urllib3", "aiohttp"},
        {"pytest", "unittest", "nose"},
        {"pyyaml", "ruamel.yaml"},
        {"black", "autopep8", "yapf"},
        {"flake8", "pylint", "pycodestyle"},
    ]

    def run(self, project_path: Path) -> list[Finding]:
        findings = []
        deps = _parse_requirements(project_path)
        dep_names = {d[0].lower() for d in deps}

        for group in self.DUPLICATE_GROUPS:
            overlap = dep_names & group
            if len(overlap) > 1:
                names = ", ".join(sorted(overlap))
                findings.append(self._make_finding(
                    message=f"Overlapping packages: {names}",
                    suggestion=f"Consider consolidating to one: {names}",
                ))

        return findings


class DEP006OutdatedPackages(DependencyCheck):
    """Check for significantly outdated packages."""

    check_id = "DEP-006"
    category = Category.DEPENDENCIES
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Significantly outdated package"

    def run(self, project_path: Path) -> list[Finding]:
        findings = []

        # Only check packages that are declared project dependencies
        project_deps = _parse_requirements(project_path)
        if not project_deps:
            return findings  # No declared deps to check

        project_dep_names = {name.lower() for name, _, _ in project_deps}

        try:
            result = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                import json
                outdated = json.loads(result.stdout)
                for pkg in outdated:
                    name = pkg.get("name", "")
                    # Only check declared project dependencies, not system packages
                    if name.lower() not in project_dep_names:
                        continue
                    current = pkg.get("version", "")
                    latest = pkg.get("latest_version", "")

                    # Check if it's a major version behind
                    try:
                        curr_major = int(current.split(".")[0])
                        latest_major = int(latest.split(".")[0])
                        if latest_major - curr_major >= 2:
                            findings.append(self._make_finding(
                                message=f"'{name}' is {latest_major - curr_major} major versions behind ({current} -> {latest})",
                                suggestion=f"Run: pip install --upgrade {name}",
                                fix_type=FixType.RULE_BASED,
                            ))
                    except (ValueError, IndexError):
                        continue
        except Exception:
            pass  # version comparison failed; skip outdated-package check

        return findings


class DEP007MissingRequirements(DependencyCheck):
    """Check for missing requirements file."""

    check_id = "DEP-007"
    category = Category.DEPENDENCIES
    severity = Severity.WARNING
    fix_type = FixType.RULE_BASED
    description = "Missing requirements file"

    REQ_FILES = (
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "poetry.lock",
    )

    def run(self, project_path: Path) -> list[Finding]:
        findings = []

        # Check project_path and up to 3 parent directories for requirements files
        has_req = False
        search_path = project_path.resolve()
        for _ in range(4):
            if any((search_path / f).exists() for f in self.REQ_FILES):
                has_req = True
                break
            parent = search_path.parent
            if parent == search_path:
                break
            search_path = parent

        if not has_req:
            # Check if there are Python files to warrant a requirements file
            py_files = list(project_path.rglob("*.py"))
            py_files = [
                f for f in py_files
                if not any(
                    p in f.parts for p in (".venv", "venv", "node_modules", ".git")
                )
            ]
            if py_files:
                findings.append(self._make_finding(
                    message="No requirements file found (requirements.txt or pyproject.toml)",
                    suggestion="Generate with: pip freeze > requirements.txt",
                    fix_type=FixType.RULE_BASED,
                ))

        return findings


class DEP008DevDepsInProd(DependencyCheck):
    """Check for dev dependencies in production requirements."""

    check_id = "DEP-008"
    category = Category.DEPENDENCIES
    severity = Severity.INFO
    fix_type = FixType.RULE_BASED
    description = "Dev dependency in production"

    DEV_PACKAGES = {
        "pytest", "pytest-cov", "pytest-asyncio", "pytest-mock",
        "black", "isort", "flake8", "mypy", "pylint",
        "autopep8", "yapf", "pycodestyle", "pydocstyle",
        "coverage", "tox", "nox", "pre-commit",
        "sphinx", "mkdocs", "pdoc",
        "ipython", "jupyter", "notebook",
        "debugpy", "ipdb", "pdb++",
        "faker", "factory-boy", "hypothesis",
    }

    def run(self, project_path: Path) -> list[Finding]:
        findings = []

        # Only check requirements.txt (not dev-specific files)
        req_file = project_path / "requirements.txt"
        if not req_file.exists():
            return findings

        deps = _parse_requirements(project_path)
        for pkg_name, _, dep_file in deps:
            if dep_file.name in ("requirements-dev.txt", "requirements/dev.txt"):
                continue
            if pkg_name.lower() in self.DEV_PACKAGES:
                findings.append(self._make_finding(
                    message=f"Dev dependency '{pkg_name}' in production requirements",
                    file_path=dep_file,
                    suggestion=f"Move '{pkg_name}' to requirements-dev.txt or [project.optional-dependencies.dev]",
                    fix_type=FixType.RULE_BASED,
                ))

        return findings
