"""Pro: Healing audit log for Guardian.

Every automatic healing action is recorded to a local append-only log
so operators can review what Guardian did and when.

Log location: ``.devnog/healing_audit.log``

Format (pipe-delimited, one line per action)::

    timestamp | action | function | error | strategy | result | duration_ms

View the log via::

    devnog guardian --audit

Requires a Pro or Enterprise license.
"""

from __future__ import annotations

import fcntl
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from devnog.core.config import get_devnog_dir


_LOG_FILENAME = "healing_audit.log"

_HEADER = (
    "# DevNog Guardian Healing Audit Log\n"
    "# Format: timestamp | action | function | error | strategy | result | duration_ms\n"
    "#\n"
)


class HealingAuditLog:
    """Append-only audit log for healing actions.

    **Pro feature** — instantiation is gated by the license manager.

    Thread-safe: writes are serialised through a lock *and* an ``fcntl``
    advisory lock so that multiple processes sharing the same project
    directory will not corrupt the file.
    """

    def __init__(self, project_path: Path | None = None) -> None:
        devnog_dir = get_devnog_dir(project_path)
        self._path = devnog_dir / _LOG_FILENAME
        self._lock = threading.Lock()
        self._ensure_header()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        *,
        action: str,
        function: str,
        error: str,
        strategy: str,
        result: str,
        duration_ms: float,
    ) -> None:
        """Append a single healing-action record to the log.

        Parameters
        ----------
        action:
            Short verb, e.g. ``"retry"``, ``"fallback"``, ``"circuit_break"``.
        function:
            Fully-qualified name of the function that was healed.
        error:
            The original error type/message (truncated to one line).
        strategy:
            Description of the healing strategy applied.
        result:
            ``"success"`` or ``"failure"`` (with optional detail).
        duration_ms:
            Wall-clock time of the healing attempt in milliseconds.
        """
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        # Sanitise pipe characters in free-text fields.
        line = " | ".join(
            [
                ts,
                _sanitise(action),
                _sanitise(function),
                _sanitise(error),
                _sanitise(strategy),
                _sanitise(result),
                f"{duration_ms:.1f}",
            ]
        )
        self._append(line + "\n")

    def read_all(self) -> str:
        """Return the full contents of the audit log as a string."""
        with self._lock:
            if not self._path.exists():
                return ""
            return self._path.read_text(encoding="utf-8")

    def read_entries(self, last_n: int = 50) -> list[dict[str, str]]:
        """Parse the last *n* entries into dicts.

        Returns a list of dicts with keys:
        ``timestamp``, ``action``, ``function``, ``error``,
        ``strategy``, ``result``, ``duration_ms``.
        """
        text = self.read_all()
        if not text:
            return []

        lines = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
        lines = lines[-last_n:]

        entries: list[dict[str, str]] = []
        for ln in lines:
            parts = [p.strip() for p in ln.split("|")]
            if len(parts) < 7:
                continue
            entries.append(
                {
                    "timestamp": parts[0],
                    "action": parts[1],
                    "function": parts[2],
                    "error": parts[3],
                    "strategy": parts[4],
                    "result": parts[5],
                    "duration_ms": parts[6],
                }
            )
        return entries

    @property
    def path(self) -> Path:
        """Return the absolute path to the audit log file."""
        return self._path

    def clear(self) -> None:
        """Truncate the log (useful in tests)."""
        with self._lock:
            self._path.write_text(_HEADER, encoding="utf-8")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_header(self) -> None:
        """Write the header comment if the file does not exist yet."""
        if not self._path.exists():
            self._path.write_text(_HEADER, encoding="utf-8")

    def _append(self, text: str) -> None:
        """Thread-safe and process-safe append."""
        with self._lock:
            fd: TextIO | None = None
            try:
                fd = open(self._path, "a", encoding="utf-8")
                # Advisory lock — non-blocking on failure (best-effort).
                try:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (OSError, IOError):
                    pass  # proceed without lock; better than dropping data
                fd.write(text)
                fd.flush()
            finally:
                if fd is not None:
                    try:
                        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
                    except (OSError, IOError):
                        pass
                    fd.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitise(value: str) -> str:
    """Replace pipes and newlines so they don't break the log format."""
    return value.replace("|", "/").replace("\n", " ").replace("\r", "")
