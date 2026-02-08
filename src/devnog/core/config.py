"""Configuration management for DevNog (devnog.toml parsing + defaults)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class ScanConfig:
    fail_under: int = 0
    categories: list[str] = field(
        default_factory=lambda: [
            "code_quality",
            "security",
            "error_handling",
            "dependencies",
        ]
    )
    max_function_length: int = 50
    max_complexity: int = 10
    ignore: list[str] = field(default_factory=list)


@dataclass
class FixConfig:
    auto_apply_safe: bool = False
    backup_before_fix: bool = True
    max_ai_fixes_per_run: int = 10
    ai_model: str = "claude-sonnet-4-20250514"
    ai_max_tokens: int = 2000


@dataclass
class CaptureConfig:
    max_captures: int = 500
    max_size_mb: int = 5
    encrypt: bool = True
    redact_sensitive: bool = True


@dataclass
class GuardianConfig:
    enable_healing: bool = False
    sample_rate: float = 1.0
    max_overhead_ms: float = 2.0
    alert_on_critical: bool = True


@dataclass
class DashboardConfig:
    port: int = 7654
    auto_open_browser: bool = True


@dataclass
class DevNogConfig:
    """Complete DevNog configuration."""

    exclude: list[str] = field(
        default_factory=lambda: [
            "venv/",
            ".venv/",
            "migrations/",
            "__pycache__/",
            ".devnog/",
            "node_modules/",
            ".git/",
        ]
    )
    scan: ScanConfig = field(default_factory=ScanConfig)
    fix: FixConfig = field(default_factory=FixConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    guardian: GuardianConfig = field(default_factory=GuardianConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)


def load_config(project_path: Path | None = None) -> DevNogConfig:
    """Load configuration from devnog.toml if present, otherwise return defaults."""
    config = DevNogConfig()

    if project_path is None:
        project_path = Path.cwd()

    config_file = project_path / "devnog.toml"
    if not config_file.exists():
        return config

    if tomllib is None:
        return config

    with open(config_file, "rb") as f:
        data = tomllib.load(f)

    if "general" in data:
        gen = data["general"]
        if "exclude" in gen:
            config.exclude = gen["exclude"]

    if "scan" in data:
        s = data["scan"]
        if "fail_under" in s:
            config.scan.fail_under = s["fail_under"]
        if "categories" in s:
            config.scan.categories = s["categories"]
        if "ignore" in s:
            config.scan.ignore = s["ignore"]
        cq = s.get("code_quality", {})
        if "max_function_length" in cq:
            config.scan.max_function_length = cq["max_function_length"]
        if "max_complexity" in cq:
            config.scan.max_complexity = cq["max_complexity"]

    if "fix" in data:
        fx = data["fix"]
        if "auto_apply_safe" in fx:
            config.fix.auto_apply_safe = fx["auto_apply_safe"]
        if "backup_before_fix" in fx:
            config.fix.backup_before_fix = fx["backup_before_fix"]
        if "max_ai_fixes_per_run" in fx:
            config.fix.max_ai_fixes_per_run = fx["max_ai_fixes_per_run"]
        ai = fx.get("ai", {})
        if "model" in ai:
            config.fix.ai_model = ai["model"]
        if "max_tokens" in ai:
            config.fix.ai_max_tokens = ai["max_tokens"]

    if "capture" in data:
        c = data["capture"]
        for attr in ("max_captures", "max_size_mb", "encrypt", "redact_sensitive"):
            if attr in c:
                setattr(config.capture, attr, c[attr])

    if "guardian" in data:
        g = data["guardian"]
        for attr in ("enable_healing", "sample_rate", "max_overhead_ms", "alert_on_critical"):
            if attr in g:
                setattr(config.guardian, attr, g[attr])

    if "dashboard" in data:
        d = data["dashboard"]
        if "port" in d:
            config.dashboard.port = d["port"]
        if "auto_open_browser" in d:
            config.dashboard.auto_open_browser = d["auto_open_browser"]

    return config


def get_devnog_dir(project_path: Path | None = None) -> Path:
    """Get or create the .devnog directory."""
    if project_path is None:
        project_path = Path.cwd()
    devnog_dir = project_path / ".devnog"
    devnog_dir.mkdir(exist_ok=True)
    return devnog_dir


def ensure_gitignore(project_path: Path | None = None) -> None:
    """Add .devnog/ to .gitignore if not already present."""
    if project_path is None:
        project_path = Path.cwd()
    gitignore = project_path / ".gitignore"
    entry = ".devnog/"

    if gitignore.exists():
        content = gitignore.read_text()
        if entry in content:
            return
        if not content.endswith("\n"):
            content += "\n"
        content += f"{entry}\n"
        gitignore.write_text(content)
    else:
        gitignore.write_text(f"{entry}\n")
