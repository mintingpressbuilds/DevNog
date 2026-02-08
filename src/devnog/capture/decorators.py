"""Decorators for the Capture/Replay module.

Three decorators are exported:

``@capture``
    Lightweight -- captures state on failure and re-raises.

``@healable``
    Tier-gated healing.  FREE tier captures and re-raises.  PRO/ENTERPRISE
    tiers add retry with exponential back-off and optional fallback
    strategies.

``@checkpoint``
    Saves intermediate state at named steps so long-running functions can
    be replayed from the last successful step.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import time
import traceback
from datetime import datetime
from typing import Any, Callable, TypeVar, overload

from devnog.capture.models import CheckpointState, FailureCapture
from devnog.capture.serializer import serialize_args, serialize_locals
from devnog.capture.store import CaptureStore

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Lazy singletons (avoid import-time side-effects)
# ---------------------------------------------------------------------------

_store: CaptureStore | None = None


def _get_store() -> CaptureStore:
    global _store
    if _store is None:
        _store = CaptureStore()
    return _store


def _get_tier():
    """Import and return the current license tier lazily."""
    from devnog.core.license import get_license_manager, Tier
    return get_license_manager().get_tier(), Tier


# ---------------------------------------------------------------------------
# Failure capture builder
# ---------------------------------------------------------------------------

def _build_failure_capture(
    func: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    exc: BaseException,
    tb_str: str,
    local_vars: dict[str, Any] | None = None,
) -> FailureCapture:
    """Construct a :class:`FailureCapture` from a caught exception."""
    safe_args, safe_kwargs = serialize_args(args, kwargs, redact=True)
    safe_locals = serialize_locals(local_vars or {}, redact=True)

    # Extract file / line from the innermost traceback frame
    file_path = ""
    line_number = 0
    tb = exc.__traceback__
    while tb is not None:
        file_path = tb.tb_frame.f_code.co_filename
        line_number = tb.tb_lineno
        tb = tb.tb_next

    return FailureCapture(
        function_name=func.__name__,
        module=func.__module__,
        error_type=type(exc).__qualname__,
        error_message=str(exc),
        traceback_str=tb_str,
        args_snapshot=safe_args,
        kwargs_snapshot=safe_kwargs,
        local_vars=safe_locals,
        timestamp=datetime.utcnow(),
        file_path=file_path,
        line_number=line_number,
    )


def _extract_local_vars(exc: BaseException) -> dict[str, Any]:
    """Try to grab locals from the innermost traceback frame."""
    tb = exc.__traceback__
    if tb is None:
        return {}
    while tb.tb_next is not None:
        tb = tb.tb_next
    try:
        return dict(tb.tb_frame.f_locals)
    except Exception:
        return {}


# =====================================================================
# @capture -- lightweight failure capture
# =====================================================================

@overload
def capture(func: F) -> F: ...
@overload
def capture(*, store: CaptureStore | None = None) -> Callable[[F], F]: ...


def capture(func: F | None = None, *, store: CaptureStore | None = None) -> F | Callable[[F], F]:
    """Capture state on failure and re-raise.

    Can be used bare (``@capture``) or with options
    (``@capture(store=my_store)``).
    """
    def decorator(fn: F) -> F:
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:
                    _handle_capture(fn, args, kwargs, exc, store)
                    raise
            return async_wrapper  # type: ignore[return-value]
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:
                    _handle_capture(fn, args, kwargs, exc, store)
                    raise
            return sync_wrapper  # type: ignore[return-value]

    if func is not None:
        # Bare @capture usage (no parentheses)
        return decorator(func)
    return decorator  # type: ignore[return-value]


def _handle_capture(
    fn: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    exc: Exception,
    store: CaptureStore | None,
) -> None:
    """Build a FailureCapture and persist it."""
    try:
        tb_str = traceback.format_exc()
        local_vars = _extract_local_vars(exc)
        fc = _build_failure_capture(fn, args, kwargs, exc, tb_str, local_vars)
        s = store or _get_store()
        capture_id = s.save_capture(fc)
        if capture_id:
            logger.debug("Captured failure %s for %s.%s", capture_id, fn.__module__, fn.__name__)
    except Exception:
        # Never let capture machinery mask the real error
        logger.debug("Failed to save capture for %s", fn.__name__, exc_info=True)


# =====================================================================
# @healable -- tier-gated healing
# =====================================================================

@overload
def healable(func: F) -> F: ...
@overload
def healable(
    *,
    retries: int = 3,
    backoff_base: float = 1.0,
    backoff_max: float = 30.0,
    fallback: Callable[..., Any] | None = None,
    store: CaptureStore | None = None,
) -> Callable[[F], F]: ...


def healable(
    func: F | None = None,
    *,
    retries: int = 3,
    backoff_base: float = 1.0,
    backoff_max: float = 30.0,
    fallback: Callable[..., Any] | None = None,
    store: CaptureStore | None = None,
) -> F | Callable[[F], F]:
    """Capture on failure; optionally heal (retry + fallback) on PRO/ENTERPRISE.

    Parameters
    ----------
    retries:
        Max retry attempts (PRO/ENTERPRISE only).
    backoff_base:
        Initial back-off delay in seconds.  Doubles each attempt.
    backoff_max:
        Maximum delay between retries.
    fallback:
        A callable invoked with the same ``(*args, **kwargs)`` when all
        retries are exhausted.  PRO/ENTERPRISE only.
    store:
        Override the default :class:`CaptureStore`.
    """
    def decorator(fn: F) -> F:
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                tier, Tier = _get_tier()
                is_paid = tier in (Tier.PRO, Tier.ENTERPRISE)

                if not is_paid:
                    # FREE tier: capture and re-raise
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as exc:
                        _handle_capture(fn, args, kwargs, exc, store)
                        raise

                # PRO/ENTERPRISE: full healing pipeline
                last_exc: Exception | None = None
                for attempt in range(retries + 1):
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as exc:
                        last_exc = exc
                        _handle_capture(fn, args, kwargs, exc, store)
                        if attempt < retries:
                            delay = min(backoff_base * (2 ** attempt), backoff_max)
                            logger.info(
                                "Healable retry %d/%d for %s.%s in %.1fs",
                                attempt + 1,
                                retries,
                                fn.__module__,
                                fn.__name__,
                                delay,
                            )
                            await asyncio.sleep(delay)

                # All retries exhausted -- try fallback
                if fallback is not None:
                    logger.info(
                        "Invoking fallback for %s.%s",
                        fn.__module__,
                        fn.__name__,
                    )
                    if asyncio.iscoroutinefunction(fallback):
                        return await fallback(*args, **kwargs)
                    return fallback(*args, **kwargs)

                raise last_exc  # type: ignore[misc]

            return async_wrapper  # type: ignore[return-value]
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                tier, Tier = _get_tier()
                is_paid = tier in (Tier.PRO, Tier.ENTERPRISE)

                if not is_paid:
                    # FREE tier: capture and re-raise
                    try:
                        return fn(*args, **kwargs)
                    except Exception as exc:
                        _handle_capture(fn, args, kwargs, exc, store)
                        raise

                # PRO/ENTERPRISE: full healing pipeline
                last_exc: Exception | None = None
                for attempt in range(retries + 1):
                    try:
                        return fn(*args, **kwargs)
                    except Exception as exc:
                        last_exc = exc
                        _handle_capture(fn, args, kwargs, exc, store)
                        if attempt < retries:
                            delay = min(backoff_base * (2 ** attempt), backoff_max)
                            logger.info(
                                "Healable retry %d/%d for %s.%s in %.1fs",
                                attempt + 1,
                                retries,
                                fn.__module__,
                                fn.__name__,
                                delay,
                            )
                            time.sleep(delay)

                # All retries exhausted -- try fallback
                if fallback is not None:
                    logger.info(
                        "Invoking fallback for %s.%s",
                        fn.__module__,
                        fn.__name__,
                    )
                    if asyncio.iscoroutinefunction(fallback):
                        loop = asyncio.get_event_loop()
                        return loop.run_until_complete(fallback(*args, **kwargs))
                    return fallback(*args, **kwargs)

                raise last_exc  # type: ignore[misc]

            return sync_wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator  # type: ignore[return-value]


# =====================================================================
# @checkpoint -- intermediate state saving
# =====================================================================

class _CheckpointContext:
    """Helper yielded inside a ``@checkpoint``-decorated function.

    The decorated function receives this object as a ``_ckpt`` keyword
    argument and calls ``_ckpt.save(step_name, state_dict)`` to persist
    intermediate state.
    """

    def __init__(
        self,
        function_name: str,
        module: str,
        args_snapshot: list,
        kwargs_snapshot: dict,
        store: CaptureStore,
    ) -> None:
        self.function_name = function_name
        self.module = module
        self._args_snapshot = args_snapshot
        self._kwargs_snapshot = kwargs_snapshot
        self._store = store
        self._step_index = 0
        self.last_id: str = ""

    def save(self, step_name: str, state: dict[str, Any]) -> str:
        """Persist a checkpoint and return its id."""
        cp = CheckpointState(
            function_name=self.function_name,
            module=self.module,
            step_name=step_name,
            step_index=self._step_index,
            state=state,
            args_snapshot=self._args_snapshot,
            kwargs_snapshot=self._kwargs_snapshot,
        )
        self._step_index += 1
        self.last_id = self._store.save_checkpoint(cp)
        logger.debug(
            "Checkpoint '%s' (step %d) saved for %s.%s",
            step_name,
            cp.step_index,
            self.module,
            self.function_name,
        )
        return self.last_id

    def mark_completed(self) -> None:
        """Mark the last checkpoint as fully completed."""
        if not self.last_id:
            return
        cp = self._store.get_checkpoint(self.last_id)
        if cp is not None:
            cp.completed = True
            self._store.save_checkpoint(cp)


@overload
def checkpoint(func: F) -> F: ...
@overload
def checkpoint(*, store: CaptureStore | None = None) -> Callable[[F], F]: ...


def checkpoint(
    func: F | None = None,
    *,
    store: CaptureStore | None = None,
) -> F | Callable[[F], F]:
    """Save intermediate state at named steps for replay.

    The decorated function receives an extra keyword argument ``_ckpt``
    (a :class:`_CheckpointContext`) that it uses to persist state::

        @checkpoint
        def my_pipeline(data, *, _ckpt=None, **kw):
            step1_result = do_step1(data)
            _ckpt.save("step1", {"result": step1_result})

            step2_result = do_step2(step1_result)
            _ckpt.save("step2", {"result": step2_result})

            return step2_result

    When replayed the function also receives ``_checkpoint_state``,
    ``_checkpoint_step_index``, and ``_checkpoint_step_name`` so it can
    skip already-completed steps.
    """
    def decorator(fn: F) -> F:
        # Detect if the function accepts a _ckpt parameter
        sig = inspect.signature(fn)
        _accepts_ckpt = (
            "_ckpt" in sig.parameters
            or any(
                p.kind == inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            )
        )

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                ckpt_ctx = _make_checkpoint_context(fn, args, kwargs, store)
                if _accepts_ckpt:
                    kwargs["_ckpt"] = ckpt_ctx
                try:
                    result = await fn(*args, **kwargs)
                    ckpt_ctx.mark_completed()
                    return result
                except Exception as exc:
                    # Also capture the failure so it shows up in the store
                    _handle_capture(fn, args, kwargs, exc, store)
                    raise
            return async_wrapper  # type: ignore[return-value]
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ckpt_ctx = _make_checkpoint_context(fn, args, kwargs, store)
                if _accepts_ckpt:
                    kwargs["_ckpt"] = ckpt_ctx
                try:
                    result = fn(*args, **kwargs)
                    ckpt_ctx.mark_completed()
                    return result
                except Exception as exc:
                    _handle_capture(fn, args, kwargs, exc, store)
                    raise
            return sync_wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator  # type: ignore[return-value]


def _make_checkpoint_context(
    fn: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    store: CaptureStore | None,
) -> _CheckpointContext:
    """Create a fresh checkpoint context for a function invocation."""
    safe_args, safe_kwargs = serialize_args(args, kwargs, redact=True)
    # Remove internal checkpoint keys from the persisted kwargs
    for internal_key in ("_ckpt", "_checkpoint_state", "_checkpoint_step_index", "_checkpoint_step_name"):
        safe_kwargs.pop(internal_key, None)
    return _CheckpointContext(
        function_name=fn.__name__,
        module=fn.__module__,
        args_snapshot=safe_args,
        kwargs_snapshot=safe_kwargs,
        store=store or _get_store(),
    )
