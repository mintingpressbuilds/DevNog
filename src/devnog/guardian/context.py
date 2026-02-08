"""Async context manager for Guardian in non-web applications.

``guardian_context`` provides the same observation and healing capabilities
as :func:`~devnog.guardian.middleware.guard`, but for long-running scripts,
CLI tools, task workers, and other non-ASGI programs::

    import asyncio
    from devnog import guardian_context, guardian_config

    async def main():
        async with guardian_context(config=guardian_config(enable_healing=True)) as ctx:
            await do_work()

    asyncio.run(main())

Kill switch
-----------
``DEVNOG_GUARDIAN=off`` disables everything — the context manager becomes
a transparent no-op.
"""

from __future__ import annotations

import logging
import sys
import time
import traceback
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from devnog.guardian.config import GuardianConfig, guardian_config, _is_guardian_disabled

logger = logging.getLogger("devnog.guardian")


# ---------------------------------------------------------------------------
# Context handle
# ---------------------------------------------------------------------------

class GuardianContext:
    """Handle returned by :func:`guardian_context`.

    Provides methods for manual observation and access to Pro features.
    """

    def __init__(self, config: GuardianConfig) -> None:
        self.config = config
        self._disabled = _is_guardian_disabled()
        self._start_time = time.monotonic()
        self._failure_count = 0

        # Pro features — lazily initialised.
        self._pattern_detector: Any | None = None
        self._audit_log: Any | None = None
        self._pro_checked = False

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def record_failure(
        self,
        exc: BaseException,
        *,
        function_name: str = "",
        module: str = "",
    ) -> None:
        """Manually record a caught exception.

        Call this when you handle an exception yourself but still want
        Guardian to track it::

            try:
                risky_call()
            except SomeError as e:
                ctx.record_failure(e, function_name="risky_call")
        """
        if self._disabled:
            return

        self._failure_count += 1
        error_type = type(exc).__qualname__
        error_message = str(exc)

        if self.config.alert_on_critical:
            logger.warning(
                "Guardian observed %s in %s: %s",
                error_type,
                function_name or "<unknown>",
                error_message,
            )

        self._ensure_pro_features()
        if self._pattern_detector is not None:
            from devnog.guardian.patterns import FailureEvent

            event = FailureEvent(
                function_name=function_name or "<manual>",
                module=module,
                error_type=error_type,
                error_message=error_message,
            )
            new_patterns = self._pattern_detector.record(event)
            for p in new_patterns:
                logger.info("Guardian pattern detected: %s", p.description)

        if self._audit_log is not None and self.config.healing_log:
            elapsed_ms = (time.monotonic() - self._start_time) * 1000
            self._audit_log.record(
                action="observe",
                function=function_name or "<manual>",
                error=f"{error_type}: {error_message}"[:200],
                strategy="none",
                result="captured",
                duration_ms=elapsed_ms,
            )

    @property
    def stats(self) -> dict[str, Any]:
        """Return lightweight counters."""
        return {
            "failures": self._failure_count,
            "uptime_s": time.monotonic() - self._start_time,
        }

    @property
    def pattern_detector(self) -> Any | None:
        """Access the underlying :class:`FailurePatternDetector` (Pro)."""
        self._ensure_pro_features()
        return self._pattern_detector

    @property
    def audit_log(self) -> Any | None:
        """Access the underlying :class:`HealingAuditLog` (Pro)."""
        self._ensure_pro_features()
        return self._audit_log

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _start(self) -> None:
        """Called when the context manager is entered."""
        self._start_time = time.monotonic()
        logger.debug("Guardian context started")

    def _stop(self) -> None:
        """Called when the context manager is exited."""
        uptime = time.monotonic() - self._start_time
        logger.debug(
            "Guardian context stopped after %.1fs (%d failures)",
            uptime,
            self._failure_count,
        )

    # ------------------------------------------------------------------
    # Pro feature bootstrapping
    # ------------------------------------------------------------------

    def _ensure_pro_features(self) -> None:
        """Lazily initialise Pro-tier components if licensed."""
        if self._pro_checked:
            return
        self._pro_checked = True

        try:
            from devnog.core.license import get_license_manager, Tier

            lm = get_license_manager()
            tier = lm.get_tier()
            if tier not in (Tier.PRO, Tier.ENTERPRISE):
                return

            from devnog.guardian.patterns import FailurePatternDetector
            from devnog.guardian.audit import HealingAuditLog

            self._pattern_detector = FailurePatternDetector()
            if self.config.healing_log:
                self._audit_log = HealingAuditLog()
        except Exception:
            logger.debug("Could not initialise Pro features", exc_info=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@asynccontextmanager
async def guardian_context(
    config: GuardianConfig | None = None,
) -> AsyncIterator[GuardianContext]:
    """Async context manager that activates Guardian for non-web code.

    Parameters
    ----------
    config:
        Optional :class:`~devnog.guardian.config.GuardianConfig`.
        Uses :func:`guardian_config` defaults when omitted.

    Yields
    ------
    :class:`GuardianContext`
        A handle for manual failure recording, stats, and access to
        Pro features (pattern detector, audit log).

    Examples
    --------
    ::

        async with guardian_context() as ctx:
            try:
                result = await some_task()
            except Exception as exc:
                ctx.record_failure(exc, function_name="some_task")
    """
    # Kill switch — return a disabled stub.
    cfg = config or guardian_config()
    ctx = GuardianContext(cfg)

    if _is_guardian_disabled():
        yield ctx
        return

    ctx._start()
    try:
        yield ctx
    except BaseException as exc:
        # Automatically record unhandled exceptions.
        ctx.record_failure(exc)
        raise
    finally:
        ctx._stop()
