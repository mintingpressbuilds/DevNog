"""Replay from checkpoint -- re-execute a decorated function starting from
the last successfully completed checkpoint rather than from scratch.

Usage::

    from devnog.capture.replayer import Replayer

    replayer = Replayer()
    result = replayer.replay("my_pipeline")           # sync
    result = await replayer.areplay("my_pipeline")     # async
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from pathlib import Path
from typing import Any, Callable

from devnog.capture.models import CheckpointState, FailureCapture
from devnog.capture.store import CaptureStore

logger = logging.getLogger(__name__)


class ReplayError(Exception):
    """Raised when a replay attempt fails."""


class Replayer:
    """Orchestrates replaying a function from its most recent checkpoint.

    The replayer:

    1. Looks up the latest :class:`CheckpointState` for the given function.
    2. Resolves the original function by module path.
    3. Injects the restored ``state`` dict into the function's keyword
       arguments so the function can skip already-completed steps.
    """

    def __init__(
        self,
        store: CaptureStore | None = None,
        project_path: Path | None = None,
    ) -> None:
        self._store = store or CaptureStore(project_path=project_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def replay(
        self,
        function_name: str,
        module: str = "",
        *,
        extra_kwargs: dict[str, Any] | None = None,
    ) -> Any:
        """Replay a synchronous function from its latest checkpoint.

        Parameters
        ----------
        function_name:
            The ``__name__`` of the decorated function.
        module:
            Fully-qualified module path (e.g. ``"myapp.pipelines"``).
            If empty, the value stored in the checkpoint is used.
        extra_kwargs:
            Additional keyword arguments merged on top of the restored
            checkpoint state.

        Returns
        -------
        Any
            The return value of the replayed function.
        """
        cp, func = self._prepare_replay(function_name, module)
        kwargs = self._build_kwargs(cp, extra_kwargs)

        logger.info(
            "Replaying %s.%s from step %d (%s)",
            cp.module,
            cp.function_name,
            cp.step_index,
            cp.step_name,
        )
        return func(*cp.args_snapshot, **kwargs)

    async def areplay(
        self,
        function_name: str,
        module: str = "",
        *,
        extra_kwargs: dict[str, Any] | None = None,
    ) -> Any:
        """Replay an async function from its latest checkpoint."""
        cp, func = self._prepare_replay(function_name, module)
        kwargs = self._build_kwargs(cp, extra_kwargs)

        logger.info(
            "Async-replaying %s.%s from step %d (%s)",
            cp.module,
            cp.function_name,
            cp.step_index,
            cp.step_name,
        )

        if asyncio.iscoroutinefunction(func):
            return await func(*cp.args_snapshot, **kwargs)
        return func(*cp.args_snapshot, **kwargs)

    def replay_capture(
        self,
        capture_id: str,
        *,
        extra_kwargs: dict[str, Any] | None = None,
    ) -> Any:
        """Re-invoke the function that produced a :class:`FailureCapture`.

        This is useful for reproducing a bug with the exact same arguments.
        """
        cap = self._store.get_capture(capture_id)
        if cap is None:
            raise ReplayError(f"Capture {capture_id!r} not found in store")

        func = self._resolve_function(cap.function_name, cap.module)
        kwargs = dict(cap.kwargs_snapshot)
        if extra_kwargs:
            kwargs.update(extra_kwargs)

        logger.info(
            "Replaying capture %s (%s.%s)",
            capture_id,
            cap.module,
            cap.function_name,
        )
        return func(*cap.args_snapshot, **kwargs)

    async def areplay_capture(
        self,
        capture_id: str,
        *,
        extra_kwargs: dict[str, Any] | None = None,
    ) -> Any:
        """Async version of :meth:`replay_capture`."""
        cap = self._store.get_capture(capture_id)
        if cap is None:
            raise ReplayError(f"Capture {capture_id!r} not found in store")

        func = self._resolve_function(cap.function_name, cap.module)
        kwargs = dict(cap.kwargs_snapshot)
        if extra_kwargs:
            kwargs.update(extra_kwargs)

        logger.info(
            "Async-replaying capture %s (%s.%s)",
            capture_id,
            cap.module,
            cap.function_name,
        )
        if asyncio.iscoroutinefunction(func):
            return await func(*cap.args_snapshot, **kwargs)
        return func(*cap.args_snapshot, **kwargs)

    def get_latest_checkpoint(
        self,
        function_name: str,
        module: str = "",
    ) -> CheckpointState | None:
        """Convenience proxy to the store's ``get_latest_checkpoint``."""
        return self._store.get_latest_checkpoint(function_name, module)

    def get_capture(self, capture_id: str) -> FailureCapture | None:
        """Convenience proxy to the store's ``get_capture``."""
        return self._store.get_capture(capture_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prepare_replay(
        self,
        function_name: str,
        module: str,
    ) -> tuple[CheckpointState, Callable[..., Any]]:
        """Load the checkpoint and resolve the function object."""
        cp = self._store.get_latest_checkpoint(function_name, module)
        if cp is None:
            raise ReplayError(
                f"No checkpoint found for function {function_name!r}"
                + (f" in module {module!r}" if module else "")
            )

        resolved_module = module or cp.module
        func = self._resolve_function(function_name, resolved_module)
        return cp, func

    @staticmethod
    def _resolve_function(name: str, module_path: str) -> Callable[..., Any]:
        """Import *module_path* and return the attribute *name*."""
        if not module_path:
            raise ReplayError(
                f"Cannot resolve function {name!r}: no module path available"
            )
        try:
            mod = importlib.import_module(module_path)
        except ImportError as exc:
            raise ReplayError(
                f"Could not import module {module_path!r}: {exc}"
            ) from exc

        func = getattr(mod, name, None)
        if func is None:
            raise ReplayError(
                f"Module {module_path!r} has no attribute {name!r}"
            )
        if not callable(func):
            raise ReplayError(
                f"{module_path}.{name} is not callable"
            )
        return func

    @staticmethod
    def _build_kwargs(
        cp: CheckpointState,
        extra_kwargs: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Merge checkpoint state into keyword arguments."""
        kwargs = dict(cp.kwargs_snapshot)
        # Inject checkpoint metadata so the function can skip steps
        kwargs["_checkpoint_state"] = cp.state
        kwargs["_checkpoint_step_index"] = cp.step_index
        kwargs["_checkpoint_step_name"] = cp.step_name
        if extra_kwargs:
            kwargs.update(extra_kwargs)
        return kwargs
