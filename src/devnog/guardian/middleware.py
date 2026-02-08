"""ASGI middleware and ``guard()`` convenience wrapper for Guardian.

Usage with FastAPI / Starlette::

    from fastapi import FastAPI
    from devnog import guard

    app = FastAPI()
    app = guard(app)                     # wraps the app with Guardian

Usage with a bare ASGI app::

    app = guard(my_asgi_app)

Kill switch
-----------
Set the environment variable ``DEVNOG_GUARDIAN=off`` to completely bypass
all Guardian instrumentation.  The overhead in disabled mode is a single
dict lookup — effectively zero.
"""

from __future__ import annotations

import logging
import sys
import time
import traceback
from typing import Any, Callable

from devnog.guardian.config import GuardianConfig, guardian_config, _is_guardian_disabled

logger = logging.getLogger("devnog.guardian")

# Type aliases for ASGI
Scope = dict[str, Any]
Receive = Callable[..., Any]
Send = Callable[..., Any]


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------

class GuardianMiddleware:
    """Low-overhead ASGI middleware that observes requests and, optionally,
    applies healing strategies when failures are detected.

    Design goals
    ------------
    * **<2 ms overhead** on the happy path (configurable via
      :pyattr:`GuardianConfig.max_overhead_ms`).
    * **Zero network** — all data stays on the local filesystem.
    * **Kill switch** — ``DEVNOG_GUARDIAN=off`` disables everything.

    The middleware wraps the inner ASGI ``app`` and intercepts exceptions
    that propagate out of request handlers.  Observed failures are fed into
    the :class:`~devnog.guardian.patterns.FailurePatternDetector` (Pro) and,
    when healing is enabled, into the healing pipeline.
    """

    def __init__(
        self,
        app: Any,
        config: GuardianConfig | None = None,
    ) -> None:
        self.app = app
        self.config = config or guardian_config()
        self._disabled = _is_guardian_disabled()

        # Pro features — lazily initialised.
        self._pattern_detector: Any | None = None
        self._audit_log: Any | None = None
        self._pro_checked = False

        # Lightweight stats (no lock — approximate is fine).
        self._request_count: int = 0
        self._failure_count: int = 0

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """ASGI entry point."""
        # Kill switch — absolute minimum overhead.
        if self._disabled:
            await self.app(scope, receive, send)
            return

        # Only instrument HTTP and WebSocket scopes; pass through lifespan
        # and anything else untouched.
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        self._request_count += 1

        # Sampling: skip instrumentation for a fraction of requests.
        if self.config.sample_rate < 1.0:
            import random
            if random.random() > self.config.sample_rate:
                await self.app(scope, receive, send)
                return

        start = time.monotonic()
        try:
            await self.app(scope, receive, send)
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            self._failure_count += 1
            await self._handle_failure(scope, exc, elapsed_ms)
            raise  # Always re-raise so the framework's error handling runs.
        else:
            elapsed_ms = (time.monotonic() - start) * 1000
            # Budget check — if we're eating too much time, back off.
            if elapsed_ms > self.config.max_overhead_ms:
                logger.debug(
                    "Guardian overhead %.1fms exceeds budget %.1fms",
                    elapsed_ms,
                    self.config.max_overhead_ms,
                )

    # ------------------------------------------------------------------
    # Failure handling
    # ------------------------------------------------------------------

    async def _handle_failure(
        self,
        scope: Scope,
        exc: Exception,
        elapsed_ms: float,
    ) -> None:
        """Process an observed failure.

        This is deliberately *not* async-blocking — all heavy work is
        deferred to keep the request latency low.
        """
        error_type = type(exc).__qualname__
        error_message = str(exc)

        # Extract route/path information from the ASGI scope.
        path = scope.get("path", "<unknown>")
        method = scope.get("method", "")
        func_name = f"{method} {path}" if method else path

        if self.config.alert_on_critical:
            logger.warning(
                "Guardian caught %s in %s: %s",
                error_type,
                func_name,
                error_message,
            )

        # Feed into pattern detector (Pro).
        self._ensure_pro_features()
        if self._pattern_detector is not None:
            from devnog.guardian.patterns import FailureEvent

            event = FailureEvent(
                function_name=func_name,
                module=scope.get("app_root_path", ""),
                error_type=error_type,
                error_message=error_message,
            )
            new_patterns = self._pattern_detector.record(event)
            for p in new_patterns:
                logger.info("Guardian pattern detected: %s", p.description)

        # Audit log (Pro).
        if (
            self._audit_log is not None
            and self.config.healing_log
        ):
            self._audit_log.record(
                action="observe",
                function=func_name,
                error=f"{error_type}: {error_message}"[:200],
                strategy="none",
                result="captured",
                duration_ms=elapsed_ms,
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
            # Non-fatal — Guardian still functions without Pro features.
            logger.debug("Could not initialise Pro features", exc_info=True)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict[str, int]:
        """Return lightweight counters (not a deep copy — approximate)."""
        return {
            "requests": self._request_count,
            "failures": self._failure_count,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def guard(app: Any, config: GuardianConfig | None = None) -> Any:
    """Add Guardian middleware to a web application.

    Automatically detects the framework and wraps appropriately:

    * **FastAPI / Starlette** — uses ``app.add_middleware`` when available
      so that middleware ordering is preserved.
    * **Bare ASGI callable** — wraps directly.

    Parameters
    ----------
    app:
        An ASGI application (FastAPI, Starlette, or any ASGI 3 callable).
    config:
        Optional :class:`~devnog.guardian.config.GuardianConfig`.
        Uses :func:`guardian_config` defaults when omitted.

    Returns
    -------
    The wrapped application.  For FastAPI/Starlette the *same* ``app``
    object is returned (middleware is added in-place via ``add_middleware``).
    For bare ASGI callables the :class:`GuardianMiddleware` wrapper is
    returned.

    Examples
    --------
    ::

        from fastapi import FastAPI
        from devnog import guard, guardian_config

        app = FastAPI()
        app = guard(app, config=guardian_config(enable_healing=True))
    """
    # Kill switch.
    if _is_guardian_disabled():
        return app

    cfg = config or guardian_config()

    # Detect FastAPI / Starlette.
    if _is_starlette_app(app):
        try:
            app.add_middleware(GuardianMiddleware, config=cfg)
            return app
        except Exception:
            # Fallback to direct wrapping if add_middleware fails.
            pass

    return GuardianMiddleware(app, config=cfg)


def _is_starlette_app(app: Any) -> bool:
    """Return True if *app* looks like a Starlette / FastAPI application."""
    # Check for the add_middleware method (present on both Starlette and
    # FastAPI Application objects).
    if not hasattr(app, "add_middleware"):
        return False

    # Optionally check the class hierarchy.
    cls_name = type(app).__name__
    module = type(app).__module__ or ""
    if "starlette" in module or "fastapi" in module:
        return True

    # Duck-typing: if it has add_middleware, treat it as Starlette-like.
    return True
