"""Guardian configuration — dataclass and factory function."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class GuardianConfig:
    """Configuration for the Guardian runtime observer.

    Attributes:
        enable_healing:  Allow Guardian to apply automatic healing strategies
                         when known failure patterns are detected.
        healing_log:     Write every healing action to the audit log
                         (``.devnog/healing_audit.log``).
        alert_on_critical: Emit a warning to stderr when a critical-level
                           failure is observed.
        sample_rate:     Fraction of requests/invocations to instrument
                         (1.0 = all, 0.1 = 10 %).
        max_overhead_ms: Performance budget.  Guardian will skip heavy
                         analysis if the overhead approaches this limit.
        capture_locals:  Include local variables in failure captures.
        max_failures:    Maximum failure records kept in memory before
                         the oldest are evicted.
        store_dir:       Directory for local storage (defaults to
                         ``.devnog/guardian``).
    """

    enable_healing: bool = False
    healing_log: bool = True
    alert_on_critical: bool = True
    sample_rate: float = 1.0
    max_overhead_ms: float = 2.0
    capture_locals: bool = True
    max_failures: int = 500
    store_dir: Path | None = None

    # ---- internal --------------------------------------------------------

    _extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.sample_rate = max(0.0, min(1.0, self.sample_rate))
        self.max_overhead_ms = max(0.1, self.max_overhead_ms)


def guardian_config(
    *,
    enable_healing: bool = False,
    healing_log: bool = True,
    alert_on_critical: bool = True,
    sample_rate: float = 1.0,
    max_overhead_ms: float = 2.0,
    capture_locals: bool = True,
    max_failures: int = 500,
    store_dir: Path | str | None = None,
    **extra: Any,
) -> GuardianConfig:
    """Create a :class:`GuardianConfig` with sensible defaults.

    This is the recommended way to build a config object::

        from devnog import guardian_config, guard

        cfg = guardian_config(enable_healing=True)
        app = guard(app, config=cfg)
    """
    resolved_dir: Path | None = None
    if store_dir is not None:
        resolved_dir = Path(store_dir)

    return GuardianConfig(
        enable_healing=enable_healing,
        healing_log=healing_log,
        alert_on_critical=alert_on_critical,
        sample_rate=sample_rate,
        max_overhead_ms=max_overhead_ms,
        capture_locals=capture_locals,
        max_failures=max_failures,
        store_dir=resolved_dir,
        _extra=extra,
    )


def _is_guardian_disabled() -> bool:
    """Return True when the kill-switch env var is active.

    Set ``DEVNOG_GUARDIAN=off`` (case-insensitive) to completely disable
    all Guardian instrumentation with zero overhead.
    """
    val = os.environ.get("DEVNOG_GUARDIAN", "").strip().lower()
    return val in ("off", "0", "false", "no", "disabled")
