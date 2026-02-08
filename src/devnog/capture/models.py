"""Data models for the Capture/Replay module."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FailureCapture:
    """Snapshot of a runtime failure for later analysis and replay.

    Captured automatically by the ``@capture`` and ``@healable`` decorators
    whenever an unhandled exception propagates.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    function_name: str = ""
    module: str = ""
    error_type: str = ""
    error_message: str = ""
    traceback_str: str = ""
    args_snapshot: list[Any] = field(default_factory=list)
    kwargs_snapshot: dict[str, Any] = field(default_factory=dict)
    local_vars: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    file_path: str = ""
    line_number: int = 0
    occurrence_count: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (datetime -> ISO string)."""
        return {
            "id": self.id,
            "function_name": self.function_name,
            "module": self.module,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "traceback_str": self.traceback_str,
            "args_snapshot": self.args_snapshot,
            "kwargs_snapshot": self.kwargs_snapshot,
            "local_vars": self.local_vars,
            "timestamp": self.timestamp.isoformat(),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "occurrence_count": self.occurrence_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FailureCapture:
        """Reconstruct from a plain dict."""
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif ts is None:
            ts = datetime.utcnow()
        return cls(
            id=data.get("id", uuid.uuid4().hex),
            function_name=data.get("function_name", ""),
            module=data.get("module", ""),
            error_type=data.get("error_type", ""),
            error_message=data.get("error_message", ""),
            traceback_str=data.get("traceback_str", ""),
            args_snapshot=data.get("args_snapshot", []),
            kwargs_snapshot=data.get("kwargs_snapshot", {}),
            local_vars=data.get("local_vars", {}),
            timestamp=ts,
            file_path=data.get("file_path", ""),
            line_number=data.get("line_number", 0),
            occurrence_count=data.get("occurrence_count", 1),
        )


@dataclass
class CheckpointState:
    """State saved at a checkpoint inside a ``@checkpoint``-decorated function.

    Checkpoints allow resuming a long-running pipeline from an
    intermediate step rather than re-running everything from scratch.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    function_name: str = ""
    module: str = ""
    step_name: str = ""
    step_index: int = 0
    state: dict[str, Any] = field(default_factory=dict)
    args_snapshot: list[Any] = field(default_factory=list)
    kwargs_snapshot: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    completed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict."""
        return {
            "id": self.id,
            "function_name": self.function_name,
            "module": self.module,
            "step_name": self.step_name,
            "step_index": self.step_index,
            "state": self.state,
            "args_snapshot": self.args_snapshot,
            "kwargs_snapshot": self.kwargs_snapshot,
            "timestamp": self.timestamp.isoformat(),
            "completed": self.completed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckpointState:
        """Reconstruct from a plain dict."""
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif ts is None:
            ts = datetime.utcnow()
        return cls(
            id=data.get("id", uuid.uuid4().hex),
            function_name=data.get("function_name", ""),
            module=data.get("module", ""),
            step_name=data.get("step_name", ""),
            step_index=data.get("step_index", 0),
            state=data.get("state", {}),
            args_snapshot=data.get("args_snapshot", []),
            kwargs_snapshot=data.get("kwargs_snapshot", {}),
            timestamp=ts,
            completed=data.get("completed", False),
        )
