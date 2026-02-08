"""Tests for capture decorators: @capture, @healable, and @checkpoint."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devnog.capture.decorators import capture, checkpoint, healable, _get_store
from devnog.capture.models import FailureCapture, CheckpointState
from devnog.capture.store import CaptureStore
from devnog.core.license import Tier, reset_license_manager


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _make_store(tmp_path: Path) -> CaptureStore:
    return CaptureStore(project_path=tmp_path)


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_license():
    """Ensure a clean license state for every test."""
    reset_license_manager()
    os.environ.pop("DEVNOG_LICENSE_KEY", None)
    yield
    reset_license_manager()
    os.environ.pop("DEVNOG_LICENSE_KEY", None)


@pytest.fixture()
def store(tmp_path: Path) -> CaptureStore:
    return _make_store(tmp_path)


# =======================================================================
# @capture
# =======================================================================

class TestCaptureDecorator:
    """@capture should capture failure state and re-raise the exception."""

    def test_successful_function_is_unaffected(self, store: CaptureStore):
        @capture(store=store)
        def add(a, b):
            return a + b

        assert add(2, 3) == 5
        assert store.capture_count() == 0

    def test_exception_is_captured_and_reraised(self, store: CaptureStore):
        @capture(store=store)
        def boom():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            boom()

        assert store.capture_count() == 1
        captures = store.list_captures()
        assert captures[0].error_type == "ValueError"
        assert captures[0].error_message == "test error"
        assert captures[0].function_name == "boom"

    def test_bare_decorator_syntax(self, tmp_path: Path):
        """@capture without parentheses should still work."""
        # We need to patch _get_store to return our test store
        store = _make_store(tmp_path)

        with patch("devnog.capture.decorators._get_store", return_value=store):
            @capture
            def fail_bare():
                raise RuntimeError("bare fail")

            with pytest.raises(RuntimeError, match="bare fail"):
                fail_bare()

        assert store.capture_count() == 1

    def test_captures_args_and_kwargs(self, store: CaptureStore):
        @capture(store=store)
        def process(x, y, mode="fast"):
            raise TypeError("bad args")

        with pytest.raises(TypeError):
            process(10, 20, mode="slow")

        captures = store.list_captures()
        assert len(captures) == 1
        fc = captures[0]
        assert fc.args_snapshot == [10, 20]
        assert fc.kwargs_snapshot.get("mode") == "slow"

    def test_async_capture(self, store: CaptureStore):
        """@capture should work on async functions."""

        @capture(store=store)
        async def async_fail():
            raise ValueError("async error")

        with pytest.raises(ValueError, match="async error"):
            asyncio.get_event_loop().run_until_complete(async_fail())

        assert store.capture_count() == 1
        captures = store.list_captures()
        assert captures[0].error_type == "ValueError"

    def test_async_success_not_captured(self, store: CaptureStore):
        @capture(store=store)
        async def async_ok():
            return 42

        result = asyncio.get_event_loop().run_until_complete(async_ok())
        assert result == 42
        assert store.capture_count() == 0

    def test_preserves_function_metadata(self, store: CaptureStore):
        @capture(store=store)
        def documented_func():
            """This is my docstring."""
            return 1

        assert documented_func.__name__ == "documented_func"
        assert "docstring" in documented_func.__doc__


# =======================================================================
# @healable
# =======================================================================

class TestHealableDecoratorFreeTier:
    """On FREE tier, @healable should capture and re-raise (no healing)."""

    def test_free_tier_captures_and_reraises(self, store: CaptureStore):
        @healable(store=store)
        def flaky():
            raise ConnectionError("network issue")

        with pytest.raises(ConnectionError, match="network issue"):
            flaky()

        assert store.capture_count() == 1
        captures = store.list_captures()
        assert captures[0].error_type == "ConnectionError"

    def test_free_tier_success(self, store: CaptureStore):
        @healable(store=store)
        def ok():
            return "fine"

        assert ok() == "fine"
        assert store.capture_count() == 0

    def test_free_tier_async(self, store: CaptureStore):
        @healable(store=store)
        async def async_flaky():
            raise IOError("async net issue")

        with pytest.raises(IOError, match="async net issue"):
            asyncio.get_event_loop().run_until_complete(async_flaky())

        assert store.capture_count() == 1

    def test_bare_healable_free_tier(self, tmp_path: Path):
        """@healable without parentheses on free tier."""
        store = _make_store(tmp_path)
        with patch("devnog.capture.decorators._get_store", return_value=store):
            @healable
            def bare_flaky():
                raise ValueError("bare error")

            with pytest.raises(ValueError, match="bare error"):
                bare_flaky()

        assert store.capture_count() == 1


class TestHealableDecoratorProTier:
    """On PRO tier, @healable should retry with backoff."""

    def _set_pro_tier(self):
        """Patch _get_tier to return PRO."""
        mock_tier_result = (Tier.PRO, Tier)
        return patch("devnog.capture.decorators._get_tier", return_value=mock_tier_result)

    def test_pro_retries_then_succeeds(self, store: CaptureStore):
        call_count = 0

        @healable(retries=3, backoff_base=0.0, store=store)
        def eventually_ok():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("not yet")
            return "healed"

        with self._set_pro_tier():
            result = eventually_ok()

        assert result == "healed"
        assert call_count == 3

    def test_pro_all_retries_exhausted_raises(self, store: CaptureStore):
        @healable(retries=2, backoff_base=0.0, store=store)
        def always_fail():
            raise RuntimeError("permanent")

        with self._set_pro_tier():
            with pytest.raises(RuntimeError, match="permanent"):
                always_fail()

    def test_pro_fallback_invoked(self, store: CaptureStore):
        def my_fallback(*args, **kwargs):
            return "fallback_result"

        @healable(retries=1, backoff_base=0.0, fallback=my_fallback, store=store)
        def always_fail():
            raise RuntimeError("fail")

        with self._set_pro_tier():
            result = always_fail()

        assert result == "fallback_result"

    def test_pro_async_retries(self, store: CaptureStore):
        call_count = 0

        @healable(retries=2, backoff_base=0.0, store=store)
        async def async_eventually_ok():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("not yet")
            return "async_healed"

        with self._set_pro_tier():
            result = asyncio.get_event_loop().run_until_complete(async_eventually_ok())

        assert result == "async_healed"
        assert call_count == 2

    def test_pro_async_fallback(self, store: CaptureStore):
        async def async_fallback(*args, **kwargs):
            return "async_fallback_result"

        @healable(retries=0, backoff_base=0.0, fallback=async_fallback, store=store)
        async def always_fail_async():
            raise RuntimeError("fail")

        with self._set_pro_tier():
            result = asyncio.get_event_loop().run_until_complete(always_fail_async())

        assert result == "async_fallback_result"

    def test_preserves_function_metadata(self, store: CaptureStore):
        @healable(store=store)
        def my_healable_func():
            """Healable docstring."""
            pass

        assert my_healable_func.__name__ == "my_healable_func"
        assert "Healable docstring" in my_healable_func.__doc__


# =======================================================================
# @checkpoint
# =======================================================================

class TestCheckpointDecorator:
    """@checkpoint injects a _ckpt context for saving intermediate state."""

    def test_checkpoint_saves_state_on_success(self, store: CaptureStore):
        @checkpoint(store=store)
        def pipeline(data, *, _ckpt=None, **kw):
            step1 = data * 2
            _ckpt.save("step1", {"result": step1})
            step2 = step1 + 10
            _ckpt.save("step2", {"result": step2})
            return step2

        result = pipeline(5)
        assert result == 20

        # Two checkpoints should be saved.
        cps = store.list_checkpoints(function_name="pipeline")
        assert len(cps) == 2

    def test_checkpoint_marks_completed_on_success(self, store: CaptureStore):
        @checkpoint(store=store)
        def simple_pipeline(*, _ckpt=None, **kw):
            _ckpt.save("only_step", {"x": 1})
            return "done"

        simple_pipeline()

        cps = store.list_checkpoints(function_name="simple_pipeline")
        # The last checkpoint should be marked completed.
        latest = store.get_latest_checkpoint("simple_pipeline")
        assert latest is not None
        assert latest.completed is True

    def test_checkpoint_captures_failure(self, store: CaptureStore):
        @checkpoint(store=store)
        def failing_pipeline(*, _ckpt=None, **kw):
            _ckpt.save("step1", {"partial": True})
            raise RuntimeError("pipeline broke at step 2")

        with pytest.raises(RuntimeError, match="pipeline broke at step 2"):
            failing_pipeline()

        # The step1 checkpoint should be saved.
        cps = store.list_checkpoints(function_name="failing_pipeline")
        assert len(cps) == 1
        assert cps[0].step_name == "step1"
        assert cps[0].completed is False

        # A failure capture should also exist.
        captures = store.list_captures(function_name="failing_pipeline")
        assert len(captures) == 1
        assert captures[0].error_type == "RuntimeError"

    def test_checkpoint_increments_step_index(self, store: CaptureStore):
        @checkpoint(store=store)
        def multi_step(*, _ckpt=None, **kw):
            _ckpt.save("a", {})
            _ckpt.save("b", {})
            _ckpt.save("c", {})
            return "ok"

        multi_step()

        cps = store.list_checkpoints(function_name="multi_step")
        indices = sorted(cp.step_index for cp in cps)
        assert indices == [0, 1, 2]

    def test_checkpoint_async(self, store: CaptureStore):
        @checkpoint(store=store)
        async def async_pipeline(*, _ckpt=None, **kw):
            _ckpt.save("step1", {"val": 42})
            return "async_done"

        result = asyncio.get_event_loop().run_until_complete(async_pipeline())
        assert result == "async_done"

        cps = store.list_checkpoints(function_name="async_pipeline")
        assert len(cps) == 1

    def test_checkpoint_async_failure(self, store: CaptureStore):
        @checkpoint(store=store)
        async def async_failing(*, _ckpt=None, **kw):
            _ckpt.save("before_crash", {"ok": True})
            raise ValueError("async crash")

        with pytest.raises(ValueError, match="async crash"):
            asyncio.get_event_loop().run_until_complete(async_failing())

        cps = store.list_checkpoints(function_name="async_failing")
        assert len(cps) == 1

        captures = store.list_captures(function_name="async_failing")
        assert len(captures) == 1

    def test_checkpoint_bare_decorator(self, tmp_path: Path):
        """@checkpoint without parentheses."""
        store = _make_store(tmp_path)
        with patch("devnog.capture.decorators._get_store", return_value=store):
            @checkpoint
            def bare_pipeline(*, _ckpt=None, **kw):
                _ckpt.save("step1", {"data": 1})
                return "bare_done"

            result = bare_pipeline()
            assert result == "bare_done"

        cps = store.list_checkpoints(function_name="bare_pipeline")
        assert len(cps) == 1

    def test_checkpoint_preserves_function_metadata(self, store: CaptureStore):
        @checkpoint(store=store)
        def my_pipeline(*, _ckpt=None):
            """Pipeline docs."""
            pass

        assert my_pipeline.__name__ == "my_pipeline"
        assert "Pipeline docs" in my_pipeline.__doc__

    def test_checkpoint_strips_internal_keys_from_kwargs(self, store: CaptureStore):
        """Internal keys like _ckpt should not be in persisted kwargs."""
        @checkpoint(store=store)
        def pipeline_with_kw(x, *, _ckpt=None, mode="default"):
            _ckpt.save("s1", {"x": x})
            return x

        pipeline_with_kw(10, mode="turbo")

        cps = store.list_checkpoints(function_name="pipeline_with_kw")
        assert len(cps) == 1
        cp = cps[0]
        assert "_ckpt" not in cp.kwargs_snapshot
        assert "_checkpoint_state" not in cp.kwargs_snapshot
