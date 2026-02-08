"""Tests for GuardianMiddleware and the guard() convenience wrapper."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from devnog.guardian.config import GuardianConfig, guardian_config
from devnog.guardian.middleware import (
    GuardianMiddleware,
    guard,
    _is_starlette_app,
)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

async def _ok_app(scope, receive, send):
    """A minimal ASGI app that always succeeds."""
    pass


async def _failing_app(scope, receive, send):
    """An ASGI app that always raises."""
    raise ValueError("app crash")


async def _lifespan_scope_app(scope, receive, send):
    """Verifies lifespan scopes pass through."""
    pass


def _http_scope(path: str = "/test", method: str = "GET") -> dict:
    return {"type": "http", "path": path, "method": method}


def _ws_scope(path: str = "/ws") -> dict:
    return {"type": "websocket", "path": path}


def _lifespan_scope() -> dict:
    return {"type": "lifespan"}


# -----------------------------------------------------------------------
# GuardianMiddleware -- happy path
# -----------------------------------------------------------------------

class TestGuardianMiddlewareHappyPath:
    @pytest.mark.asyncio
    async def test_successful_request_passes_through(self):
        mw = GuardianMiddleware(_ok_app)
        scope = _http_scope()
        await mw(scope, AsyncMock(), AsyncMock())
        assert mw.stats["requests"] == 1
        assert mw.stats["failures"] == 0

    @pytest.mark.asyncio
    async def test_websocket_scope_instrumented(self):
        mw = GuardianMiddleware(_ok_app)
        scope = _ws_scope()
        await mw(scope, AsyncMock(), AsyncMock())
        assert mw.stats["requests"] == 1

    @pytest.mark.asyncio
    async def test_lifespan_scope_passes_through(self):
        calls = []

        async def track_app(scope, receive, send):
            calls.append(scope["type"])

        mw = GuardianMiddleware(track_app)
        scope = _lifespan_scope()
        await mw(scope, AsyncMock(), AsyncMock())
        assert "lifespan" in calls
        # Lifespan should not be counted as a request.
        assert mw.stats["requests"] == 0

    @pytest.mark.asyncio
    async def test_multiple_requests_counted(self):
        mw = GuardianMiddleware(_ok_app)
        for _ in range(5):
            await mw(_http_scope(), AsyncMock(), AsyncMock())
        assert mw.stats["requests"] == 5


# -----------------------------------------------------------------------
# GuardianMiddleware -- failure handling
# -----------------------------------------------------------------------

class TestGuardianMiddlewareFailure:
    @pytest.mark.asyncio
    async def test_exception_reraised(self):
        mw = GuardianMiddleware(_failing_app)
        with pytest.raises(ValueError, match="app crash"):
            await mw(_http_scope(), AsyncMock(), AsyncMock())

    @pytest.mark.asyncio
    async def test_failure_count_incremented(self):
        mw = GuardianMiddleware(_failing_app)
        with pytest.raises(ValueError):
            await mw(_http_scope(), AsyncMock(), AsyncMock())
        assert mw.stats["failures"] == 1

    @pytest.mark.asyncio
    async def test_multiple_failures_tracked(self):
        mw = GuardianMiddleware(_failing_app)
        for _ in range(3):
            with pytest.raises(ValueError):
                await mw(_http_scope(), AsyncMock(), AsyncMock())
        assert mw.stats["failures"] == 3
        assert mw.stats["requests"] == 3


# -----------------------------------------------------------------------
# GuardianMiddleware -- kill switch
# -----------------------------------------------------------------------

class TestGuardianMiddlewareKillSwitch:
    @pytest.mark.asyncio
    async def test_disabled_passes_through_directly(self, monkeypatch):
        monkeypatch.setenv("DEVNOG_GUARDIAN", "off")
        mw = GuardianMiddleware(_ok_app)
        await mw(_http_scope(), AsyncMock(), AsyncMock())
        # Requests are NOT counted when disabled.
        assert mw.stats["requests"] == 0

    @pytest.mark.asyncio
    async def test_disabled_still_propagates_exceptions(self, monkeypatch):
        monkeypatch.setenv("DEVNOG_GUARDIAN", "off")
        mw = GuardianMiddleware(_failing_app)
        with pytest.raises(ValueError, match="app crash"):
            await mw(_http_scope(), AsyncMock(), AsyncMock())


# -----------------------------------------------------------------------
# GuardianMiddleware -- sampling
# -----------------------------------------------------------------------

class TestGuardianMiddlewareSampling:
    @pytest.mark.asyncio
    async def test_zero_sample_rate_skips_instrumentation(self):
        cfg = guardian_config(sample_rate=0.0)
        mw = GuardianMiddleware(_ok_app, config=cfg)
        await mw(_http_scope(), AsyncMock(), AsyncMock())
        # Request is counted (pre-sampling) but app is called directly.
        assert mw.stats["requests"] == 1


# -----------------------------------------------------------------------
# GuardianMiddleware -- config
# -----------------------------------------------------------------------

class TestGuardianMiddlewareConfig:
    def test_default_config_used_when_none(self):
        mw = GuardianMiddleware(_ok_app)
        assert isinstance(mw.config, GuardianConfig)
        assert mw.config.sample_rate == 1.0

    def test_custom_config(self):
        cfg = guardian_config(enable_healing=True, max_overhead_ms=10.0)
        mw = GuardianMiddleware(_ok_app, config=cfg)
        assert mw.config.enable_healing is True
        assert mw.config.max_overhead_ms == 10.0


# -----------------------------------------------------------------------
# guard() convenience function
# -----------------------------------------------------------------------

class TestGuardFunction:
    def test_guard_wraps_bare_asgi_app(self):
        result = guard(_ok_app)
        assert isinstance(result, GuardianMiddleware)

    def test_guard_with_custom_config(self):
        cfg = guardian_config(enable_healing=True)
        result = guard(_ok_app, config=cfg)
        assert isinstance(result, GuardianMiddleware)
        assert result.config.enable_healing is True

    def test_guard_kill_switch_returns_original(self, monkeypatch):
        monkeypatch.setenv("DEVNOG_GUARDIAN", "off")
        result = guard(_ok_app)
        # When disabled, should return the original app, not wrapped.
        assert result is _ok_app

    def test_guard_starlette_like_app_uses_add_middleware(self):
        """If the app has add_middleware, guard() should call it."""
        mock_app = MagicMock()
        mock_app.add_middleware = MagicMock()
        # Make it look like Starlette
        type(mock_app).__name__ = "Starlette"
        type(mock_app).__module__ = "starlette.applications"

        result = guard(mock_app)
        mock_app.add_middleware.assert_called_once()
        assert result is mock_app


# -----------------------------------------------------------------------
# _is_starlette_app detection
# -----------------------------------------------------------------------

class TestIsStarletteApp:
    def test_no_add_middleware(self):
        obj = object()
        assert _is_starlette_app(obj) is False

    def test_with_add_middleware(self):
        mock = MagicMock()
        mock.add_middleware = MagicMock()
        assert _is_starlette_app(mock) is True

    def test_starlette_module_detection(self):
        mock = MagicMock(spec=["add_middleware"])
        type(mock).__module__ = "starlette.applications"
        assert _is_starlette_app(mock) is True
