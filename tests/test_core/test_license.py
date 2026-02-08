"""Tests for license key validation (free, pro, enterprise, expired, invalid)."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from devnog.core.license import LicenseManager, Tier, License, reset_license_manager


def _make_key(tier: str, valid_until: str | None = None, seats: int = 1, holder: str = "test@example.com") -> str:
    """Create a base64-encoded license key."""
    payload = {
        "tier": tier,
        "seats": seats,
        "holder": holder,
    }
    if valid_until is not None:
        payload["valid_until"] = valid_until
    raw = json.dumps(payload).encode()
    # Remove trailing == padding that we add back in decode
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.fixture(autouse=True)
def _reset_license():
    """Reset the license manager singleton before each test."""
    reset_license_manager()
    # Clear any env var
    os.environ.pop("DEVNOG_LICENSE_KEY", None)
    yield
    reset_license_manager()
    os.environ.pop("DEVNOG_LICENSE_KEY", None)


class TestLicenseManagerFreeTier:
    def test_no_key_returns_free(self):
        """Without any key, should return FREE tier."""
        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.FREE
        assert license.seats == 1

    def test_get_tier_returns_free(self):
        """get_tier() without key should return FREE."""
        mgr = LicenseManager()
        assert mgr.get_tier() == Tier.FREE

    def test_get_license_returns_free(self):
        """get_license() without key should return FREE License."""
        mgr = LicenseManager()
        lic = mgr.get_license()
        assert isinstance(lic, License)
        assert lic.tier == Tier.FREE


class TestLicenseManagerProTier:
    def test_valid_pro_key_from_env(self):
        """A valid PRO key from env var should return PRO tier."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("pro", valid_until=future)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.PRO
        assert license.holder == "test@example.com"

    def test_require_pro_passes(self):
        """require_pro() with PRO key should return True."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("pro", valid_until=future)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        assert mgr.require_pro("AI Fixes") is True

    def test_require_pro_fails_on_free(self):
        """require_pro() with FREE tier should return False."""
        mgr = LicenseManager()
        assert mgr.require_pro("AI Fixes") is False


class TestLicenseManagerEnterpriseTier:
    def test_valid_enterprise_key(self):
        """A valid ENTERPRISE key should return ENTERPRISE tier."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("enterprise", valid_until=future, seats=50, holder="acme-corp")
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.ENTERPRISE
        assert license.seats == 50
        assert license.holder == "acme-corp"

    def test_require_enterprise_passes(self):
        """require_enterprise() with ENTERPRISE key should return True."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("enterprise", valid_until=future)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        assert mgr.require_enterprise("CI/CD Gate") is True

    def test_require_enterprise_fails_on_pro(self):
        """require_enterprise() with PRO tier should return False."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("pro", valid_until=future)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        assert mgr.require_enterprise("CI/CD Gate") is False

    def test_require_enterprise_fails_on_free(self):
        """require_enterprise() with FREE tier should return False."""
        mgr = LicenseManager()
        assert mgr.require_enterprise("CI/CD Gate") is False


class TestLicenseManagerExpiredKey:
    def test_expired_key_falls_back_to_free(self):
        """An expired key should fall back to FREE tier."""
        past = (datetime.now() - timedelta(days=30)).isoformat()
        key = _make_key("pro", valid_until=past)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.FREE

    def test_expired_enterprise_falls_back(self):
        """Expired ENTERPRISE key should also fall back to FREE."""
        past = (datetime.now() - timedelta(days=1)).isoformat()
        key = _make_key("enterprise", valid_until=past)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.FREE


class TestLicenseManagerInvalidKey:
    def test_invalid_base64_falls_back_to_free(self):
        """An invalid base64 key should fall back to FREE tier."""
        os.environ["DEVNOG_LICENSE_KEY"] = "not-valid-base64!!!"

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.FREE

    def test_invalid_json_falls_back_to_free(self):
        """A key with invalid JSON payload should fall back to FREE."""
        raw = b"this is not json"
        key = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.FREE

    def test_invalid_tier_falls_back_to_free(self):
        """A key with an invalid tier value should fall back to FREE."""
        raw = json.dumps({"tier": "platinum"}).encode()
        key = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.FREE


class TestLicenseManagerKeyFile:
    def test_reads_key_from_file(self, tmp_path: Path):
        """License key should be read from .devnog/license.key file."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("pro", valid_until=future)

        key_dir = tmp_path / ".devnog"
        key_dir.mkdir()
        (key_dir / "license.key").write_text(key)

        mgr = LicenseManager(project_path=tmp_path)
        license = mgr.load()
        assert license.tier == Tier.PRO

    def test_env_var_takes_precedence(self, tmp_path: Path):
        """Env var should take precedence over key file."""
        future = (datetime.now() + timedelta(days=365)).isoformat()

        # File has enterprise key
        file_key = _make_key("enterprise", valid_until=future)
        key_dir = tmp_path / ".devnog"
        key_dir.mkdir()
        (key_dir / "license.key").write_text(file_key)

        # Env has pro key
        env_key = _make_key("pro", valid_until=future)
        os.environ["DEVNOG_LICENSE_KEY"] = env_key

        mgr = LicenseManager(project_path=tmp_path)
        license = mgr.load()
        # Env var is checked first
        assert license.tier == Tier.PRO


class TestLicenseManagerCaching:
    def test_caches_license(self):
        """After first load, get_tier() should use cached value."""
        future = (datetime.now() + timedelta(days=365)).isoformat()
        key = _make_key("pro", valid_until=future)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        tier1 = mgr.get_tier()
        assert tier1 == Tier.PRO

        # Remove key; cached value should still return PRO
        del os.environ["DEVNOG_LICENSE_KEY"]
        tier2 = mgr.get_tier()
        assert tier2 == Tier.PRO


class TestLicensePerpetual:
    def test_no_expiry_perpetual(self):
        """A key without valid_until should be treated as perpetual."""
        key = _make_key("pro", valid_until=None)
        os.environ["DEVNOG_LICENSE_KEY"] = key

        mgr = LicenseManager()
        license = mgr.load()
        assert license.tier == Tier.PRO
        assert license.valid_until is None
