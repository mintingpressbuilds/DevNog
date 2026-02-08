"""Tests for config loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.core.config import load_config, DevNogConfig, ScanConfig, FixConfig


class TestLoadConfig:
    def test_defaults_when_no_config_file(self, tmp_path: Path):
        """Without a devnog.toml, load_config should return defaults."""
        config = load_config(tmp_path)

        assert isinstance(config, DevNogConfig)
        assert config.scan.max_function_length == 50
        assert config.scan.max_complexity == 10
        assert "code_quality" in config.scan.categories
        assert "security" in config.scan.categories
        assert "error_handling" in config.scan.categories
        assert "dependencies" in config.scan.categories

    def test_defaults_exclude_patterns(self, tmp_path: Path):
        """Default config should exclude common directories."""
        config = load_config(tmp_path)

        assert "venv/" in config.exclude
        assert ".venv/" in config.exclude
        assert "__pycache__/" in config.exclude
        assert ".git/" in config.exclude

    def test_loads_toml_scan_section(self, tmp_path: Path):
        """Scan section in devnog.toml should override defaults."""
        toml_content = """\
[scan]
fail_under = 80
categories = ["security", "error_handling"]
ignore = ["CQ-005", "CQ-006"]

[scan.code_quality]
max_function_length = 30
max_complexity = 5
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.scan.fail_under == 80
        assert config.scan.categories == ["security", "error_handling"]
        assert "CQ-005" in config.scan.ignore
        assert config.scan.max_function_length == 30
        assert config.scan.max_complexity == 5

    def test_loads_toml_general_section(self, tmp_path: Path):
        """General section in devnog.toml should override exclude patterns."""
        toml_content = """\
[general]
exclude = ["vendor/", "build/"]
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.exclude == ["vendor/", "build/"]

    def test_loads_toml_fix_section(self, tmp_path: Path):
        """Fix section in devnog.toml should override fix defaults."""
        toml_content = """\
[fix]
auto_apply_safe = true
backup_before_fix = false
max_ai_fixes_per_run = 5
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.fix.auto_apply_safe is True
        assert config.fix.backup_before_fix is False
        assert config.fix.max_ai_fixes_per_run == 5

    def test_loads_toml_fix_ai_section(self, tmp_path: Path):
        """Fix AI sub-section should override AI model settings."""
        toml_content = """\
[fix]
[fix.ai]
model = "gpt-4"
max_tokens = 4000
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.fix.ai_model == "gpt-4"
        assert config.fix.ai_max_tokens == 4000

    def test_loads_toml_capture_section(self, tmp_path: Path):
        """Capture section should override capture defaults."""
        toml_content = """\
[capture]
max_captures = 100
max_size_mb = 10
encrypt = false
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.capture.max_captures == 100
        assert config.capture.max_size_mb == 10
        assert config.capture.encrypt is False

    def test_loads_toml_dashboard_section(self, tmp_path: Path):
        """Dashboard section should override dashboard defaults."""
        toml_content = """\
[dashboard]
port = 9999
auto_open_browser = false
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.dashboard.port == 9999
        assert config.dashboard.auto_open_browser is False

    def test_partial_config_keeps_defaults(self, tmp_path: Path):
        """A partial config should only override specified fields."""
        toml_content = """\
[scan]
fail_under = 90
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.scan.fail_under == 90
        # Other defaults should be preserved
        assert config.scan.max_function_length == 50
        assert config.scan.max_complexity == 10

    def test_empty_toml_returns_defaults(self, tmp_path: Path):
        """An empty devnog.toml should return all defaults."""
        (tmp_path / "devnog.toml").write_text("")
        config = load_config(tmp_path)

        assert config.scan.max_function_length == 50
        assert config.fix.backup_before_fix is True

    def test_loads_guardian_section(self, tmp_path: Path):
        """Guardian section should override guardian defaults."""
        toml_content = """\
[guardian]
enable_healing = true
sample_rate = 0.5
max_overhead_ms = 5.0
"""
        (tmp_path / "devnog.toml").write_text(toml_content)
        config = load_config(tmp_path)

        assert config.guardian.enable_healing is True
        assert config.guardian.sample_rate == 0.5
        assert config.guardian.max_overhead_ms == 5.0


class TestDevNogConfigDefaults:
    def test_scan_config_defaults(self):
        """ScanConfig should have sensible defaults."""
        sc = ScanConfig()
        assert sc.fail_under == 0
        assert sc.max_function_length == 50
        assert sc.max_complexity == 10
        assert sc.ignore == []

    def test_fix_config_defaults(self):
        """FixConfig should have sensible defaults."""
        fc = FixConfig()
        assert fc.auto_apply_safe is False
        assert fc.backup_before_fix is True
        assert fc.max_ai_fixes_per_run == 10

    def test_devnog_config_defaults(self):
        """DevNogConfig should compose all sub-configs."""
        config = DevNogConfig()
        assert isinstance(config.scan, ScanConfig)
        assert isinstance(config.fix, FixConfig)
        assert len(config.exclude) > 0
