"""Tests for GuardianConfig and its factory function."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from devnog.guardian.config import (
    GuardianConfig,
    guardian_config,
    _is_guardian_disabled,
)


# -----------------------------------------------------------------------
# GuardianConfig dataclass
# -----------------------------------------------------------------------

class TestGuardianConfig:
    def test_default_values(self):
        cfg = GuardianConfig()
        assert cfg.enable_healing is False
        assert cfg.healing_log is True
        assert cfg.alert_on_critical is True
        assert cfg.sample_rate == 1.0
        assert cfg.max_overhead_ms == 2.0
        assert cfg.capture_locals is True
        assert cfg.max_failures == 500
        assert cfg.store_dir is None

    def test_sample_rate_clamped_to_0_1(self):
        cfg = GuardianConfig(sample_rate=2.5)
        assert cfg.sample_rate == 1.0

    def test_sample_rate_clamped_to_0_low(self):
        cfg = GuardianConfig(sample_rate=-0.5)
        assert cfg.sample_rate == 0.0

    def test_max_overhead_minimum(self):
        cfg = GuardianConfig(max_overhead_ms=0.01)
        assert cfg.max_overhead_ms == 0.1

    def test_custom_values(self):
        cfg = GuardianConfig(
            enable_healing=True,
            healing_log=False,
            alert_on_critical=False,
            sample_rate=0.5,
            max_overhead_ms=10.0,
            capture_locals=False,
            max_failures=100,
            store_dir=Path("/tmp/guard"),
        )
        assert cfg.enable_healing is True
        assert cfg.healing_log is False
        assert cfg.alert_on_critical is False
        assert cfg.sample_rate == 0.5
        assert cfg.max_overhead_ms == 10.0
        assert cfg.capture_locals is False
        assert cfg.max_failures == 100
        assert cfg.store_dir == Path("/tmp/guard")

    def test_extra_dict_default(self):
        cfg = GuardianConfig()
        assert cfg._extra == {}


# -----------------------------------------------------------------------
# guardian_config factory
# -----------------------------------------------------------------------

class TestGuardianConfigFactory:
    def test_default_factory(self):
        cfg = guardian_config()
        assert isinstance(cfg, GuardianConfig)
        assert cfg.enable_healing is False
        assert cfg.sample_rate == 1.0

    def test_factory_with_overrides(self):
        cfg = guardian_config(
            enable_healing=True,
            sample_rate=0.3,
            max_overhead_ms=5.0,
        )
        assert cfg.enable_healing is True
        assert cfg.sample_rate == 0.3
        assert cfg.max_overhead_ms == 5.0

    def test_factory_store_dir_string(self):
        cfg = guardian_config(store_dir="/tmp/my_guard")
        assert cfg.store_dir == Path("/tmp/my_guard")

    def test_factory_store_dir_path(self):
        cfg = guardian_config(store_dir=Path("/var/guard"))
        assert cfg.store_dir == Path("/var/guard")

    def test_factory_store_dir_none(self):
        cfg = guardian_config(store_dir=None)
        assert cfg.store_dir is None

    def test_factory_extra_kwargs(self):
        cfg = guardian_config(custom_flag=True, custom_val=42)
        assert cfg._extra == {"custom_flag": True, "custom_val": 42}


# -----------------------------------------------------------------------
# _is_guardian_disabled (kill switch)
# -----------------------------------------------------------------------

class TestIsGuardianDisabled:
    @pytest.mark.parametrize(
        "env_val",
        ["off", "OFF", "Off", "0", "false", "False", "FALSE", "no", "No", "disabled", "DISABLED"],
    )
    def test_disabled_values(self, monkeypatch, env_val: str):
        monkeypatch.setenv("DEVNOG_GUARDIAN", env_val)
        assert _is_guardian_disabled() is True

    @pytest.mark.parametrize(
        "env_val",
        ["on", "1", "true", "yes", "enabled", "anything_else"],
    )
    def test_enabled_values(self, monkeypatch, env_val: str):
        monkeypatch.setenv("DEVNOG_GUARDIAN", env_val)
        assert _is_guardian_disabled() is False

    def test_unset_is_not_disabled(self, monkeypatch):
        monkeypatch.delenv("DEVNOG_GUARDIAN", raising=False)
        assert _is_guardian_disabled() is False

    def test_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("DEVNOG_GUARDIAN", "  off  ")
        assert _is_guardian_disabled() is True

    def test_empty_string_is_not_disabled(self, monkeypatch):
        monkeypatch.setenv("DEVNOG_GUARDIAN", "")
        assert _is_guardian_disabled() is False
