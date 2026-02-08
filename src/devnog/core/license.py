"""License key validation and tier gating system."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)


class Tier(Enum):
    """License tier levels for feature gating."""

    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class License:
    """Decoded license information including tier, expiry, and holder."""

    tier: Tier
    valid_until: datetime | None  # None = perpetual (free tier)
    seats: int  # 1 for individual, N for enterprise
    holder: str  # Email or org name


_license_manager: LicenseManager | None = None


class LicenseManager:
    """
    Singleton. Accessed via get_license_manager().
    Checks license key on startup. Result cached for session.
    """

    def __init__(self, project_path: Path | None = None):
        self._license: License | None = None
        self._project_path = project_path or Path.cwd()

    def load(self) -> License:
        """
        1. Check DEVNOG_LICENSE_KEY env var
        2. If not set, check .devnog/license.key file
        3. If neither exists -> Free tier (fully functional)
        4. If key exists -> validate and decode
        5. Cache result for session
        """
        key = os.environ.get("DEVNOG_LICENSE_KEY") or self._read_key_file()
        if not key:
            return License(tier=Tier.FREE, valid_until=None, seats=1, holder="")

        return self._validate_and_decode(key)

    def get_tier(self) -> Tier:
        """Return current tier. <1ms (cached)."""
        if not self._license:
            self._license = self.load()
        return self._license.tier

    def get_license(self) -> License:
        """Return full license info."""
        if not self._license:
            self._license = self.load()
        return self._license

    def require_pro(self, feature_name: str) -> bool:
        """
        Check if Pro or higher. If not, print friendly upgrade message.
        Returns True if allowed, False if not.
        """
        tier = self.get_tier()
        if tier in (Tier.PRO, Tier.ENTERPRISE):
            return True
        console.print(
            f"\n[yellow]>>> [bold]{feature_name}[/bold] requires DevNog Pro.[/yellow]"
            "\n[dim]Upgrade at https://devnog.dev/pro[/dim]\n"
        )
        return False

    def require_enterprise(self, feature_name: str) -> bool:
        """Check if Enterprise tier. Print upgrade message if not."""
        tier = self.get_tier()
        if tier == Tier.ENTERPRISE:
            return True
        console.print(
            f"\n[yellow]>>> [bold]{feature_name}[/bold] requires DevNog Enterprise.[/yellow]"
            "\n[dim]Learn more at https://devnog.dev/enterprise[/dim]\n"
        )
        return False

    def _read_key_file(self) -> str | None:
        """Read license key from .devnog/license.key file."""
        key_file = self._project_path / ".devnog" / "license.key"
        if key_file.exists():
            return key_file.read_text().strip()
        return None

    def _validate_and_decode(self, key: str) -> License:
        """
        Validate license key and decode tier/expiry/seats.

        Key format: base64-encoded JSON payload.
        In production, this would use Ed25519 signature verification.
        For now, we decode the payload and validate structure.
        """
        try:
            payload_bytes = base64.urlsafe_b64decode(key + "==")
            payload = json.loads(payload_bytes)

            tier_str = payload.get("tier", "free")
            tier = Tier(tier_str)

            valid_until = None
            if "valid_until" in payload and payload["valid_until"]:
                valid_until = datetime.fromisoformat(payload["valid_until"])
                if valid_until < datetime.now():
                    console.print(
                        "[yellow]License key has expired. Falling back to Free tier.[/yellow]"
                    )
                    return License(
                        tier=Tier.FREE, valid_until=None, seats=1, holder=""
                    )

            seats = payload.get("seats", 1)
            holder = payload.get("holder", "")

            return License(
                tier=tier,
                valid_until=valid_until,
                seats=seats,
                holder=holder,
            )
        except Exception:
            console.print(
                "[yellow]Invalid license key. Falling back to Free tier.[/yellow]"
            )
            return License(tier=Tier.FREE, valid_until=None, seats=1, holder="")


def get_license_manager(project_path: Path | None = None) -> LicenseManager:
    """Get the singleton LicenseManager instance."""
    global _license_manager
    if _license_manager is None:
        _license_manager = LicenseManager(project_path)
    return _license_manager


def reset_license_manager() -> None:
    """Reset the singleton (for testing)."""
    global _license_manager
    _license_manager = None
