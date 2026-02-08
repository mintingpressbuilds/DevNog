"""Encrypted SQLite storage for failure captures and checkpoints.

The database lives at ``{project_root}/.devnog/captures.db``.  All payloads
are Fernet-encrypted before they hit disk, and automatically decrypted on
read.  The store enforces hard limits (max 500 captures, max 5 MB per
individual capture) and auto-prunes the oldest entries when the cap is hit.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from devnog.capture.models import CheckpointState, FailureCapture
from devnog.capture.serializer import safe_serialize, safe_deserialize
from devnog.core.config import get_devnog_dir, load_config
from devnog.core.crypto import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_CAPTURES = 500
DEFAULT_MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB per capture

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS captures (
    id            TEXT PRIMARY KEY,
    function_name TEXT NOT NULL,
    module        TEXT NOT NULL DEFAULT '',
    error_type    TEXT NOT NULL DEFAULT '',
    payload       BLOB NOT NULL,
    timestamp     TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id            TEXT PRIMARY KEY,
    function_name TEXT NOT NULL,
    module        TEXT NOT NULL DEFAULT '',
    step_name     TEXT NOT NULL DEFAULT '',
    step_index    INTEGER NOT NULL DEFAULT 0,
    payload       BLOB NOT NULL,
    timestamp     TEXT NOT NULL,
    completed     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_captures_ts ON captures(timestamp);
CREATE INDEX IF NOT EXISTS idx_captures_fn ON captures(function_name);
CREATE INDEX IF NOT EXISTS idx_checkpoints_fn ON checkpoints(function_name);
CREATE INDEX IF NOT EXISTS idx_checkpoints_ts ON checkpoints(timestamp);
"""


class CaptureStore:
    """Thread-safe, encrypted SQLite store for captures and checkpoints.

    Usage::

        store = CaptureStore()          # uses cwd-based .devnog dir
        store.save_capture(failure)
        store.save_checkpoint(cp)
        recent = store.list_captures(limit=20)
    """

    def __init__(
        self,
        project_path: Path | None = None,
        max_captures: int | None = None,
        max_size_bytes: int | None = None,
    ) -> None:
        self._devnog_dir = get_devnog_dir(project_path)
        self._db_path = self._devnog_dir / "captures.db"

        cfg = load_config(project_path)
        self._max_captures = max_captures or cfg.capture.max_captures or DEFAULT_MAX_CAPTURES
        self._max_size_bytes = max_size_bytes or (cfg.capture.max_size_mb * 1024 * 1024) or DEFAULT_MAX_SIZE_BYTES
        self._encrypt = cfg.capture.encrypt

        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def _encrypt_payload(self, data: str) -> bytes:
        raw = data.encode("utf-8")
        if self._encrypt:
            return encrypt_data(raw, self._devnog_dir)
        return raw

    def _decrypt_payload(self, blob: bytes) -> str:
        if self._encrypt:
            raw = decrypt_data(blob, self._devnog_dir)
        else:
            raw = blob
        return raw.decode("utf-8")

    # ------------------------------------------------------------------
    # Captures
    # ------------------------------------------------------------------

    def save_capture(self, capture: FailureCapture) -> str:
        """Persist a :class:`FailureCapture`.  Returns the capture id.

        If the serialised payload exceeds *max_size_bytes* the capture is
        silently dropped and an empty string is returned.
        """
        payload_json = safe_serialize(capture.to_dict(), redact=True)

        if len(payload_json.encode("utf-8")) > self._max_size_bytes:
            logger.warning(
                "Capture %s exceeds max size (%d bytes) -- dropped",
                capture.id,
                self._max_size_bytes,
            )
            return ""

        encrypted = self._encrypt_payload(payload_json)

        with self._lock, self._connect() as conn:
            # Check for existing capture of the same function + error combo
            existing = conn.execute(
                "SELECT id, occurrence_count FROM captures "
                "WHERE function_name = ? AND error_type = ? "
                "ORDER BY timestamp DESC LIMIT 1",
                (capture.function_name, capture.error_type),
            ).fetchone()

            if existing:
                new_count = existing["occurrence_count"] + 1
                capture.occurrence_count = new_count
                # Re-serialise with updated count
                payload_json = safe_serialize(capture.to_dict(), redact=True)
                encrypted = self._encrypt_payload(payload_json)
                conn.execute(
                    "UPDATE captures SET payload = ?, timestamp = ?, occurrence_count = ? "
                    "WHERE id = ?",
                    (encrypted, capture.timestamp.isoformat(), new_count, existing["id"]),
                )
                capture.id = existing["id"]
            else:
                conn.execute(
                    "INSERT INTO captures (id, function_name, module, error_type, payload, timestamp, occurrence_count) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        capture.id,
                        capture.function_name,
                        capture.module,
                        capture.error_type,
                        encrypted,
                        capture.timestamp.isoformat(),
                        capture.occurrence_count,
                    ),
                )

            self._prune_captures(conn)

        return capture.id

    def get_capture(self, capture_id: str) -> FailureCapture | None:
        """Retrieve a single capture by id."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM captures WHERE id = ?",
                (capture_id,),
            ).fetchone()
        if row is None:
            return None
        data = safe_deserialize(self._decrypt_payload(row["payload"]))
        if isinstance(data, dict):
            return FailureCapture.from_dict(data)
        return None

    def list_captures(
        self,
        *,
        limit: int = 50,
        function_name: str | None = None,
    ) -> list[FailureCapture]:
        """Return recent captures, newest first."""
        query = "SELECT payload FROM captures"
        params: list[Any] = []
        if function_name:
            query += " WHERE function_name = ?"
            params.append(function_name)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        captures: list[FailureCapture] = []
        for row in rows:
            data = safe_deserialize(self._decrypt_payload(row["payload"]))
            if isinstance(data, dict):
                captures.append(FailureCapture.from_dict(data))
        return captures

    def delete_capture(self, capture_id: str) -> bool:
        """Delete a single capture.  Returns ``True`` if a row was removed."""
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM captures WHERE id = ?", (capture_id,))
            return cur.rowcount > 0

    def clear_captures(self) -> int:
        """Delete **all** captures.  Returns the number removed."""
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM captures")
            return cur.rowcount

    def capture_count(self) -> int:
        """Return the current number of stored captures."""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM captures").fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Checkpoints
    # ------------------------------------------------------------------

    def save_checkpoint(self, cp: CheckpointState) -> str:
        """Persist a :class:`CheckpointState`.  Returns the checkpoint id."""
        payload_json = safe_serialize(cp.to_dict(), redact=True)

        if len(payload_json.encode("utf-8")) > self._max_size_bytes:
            logger.warning(
                "Checkpoint %s exceeds max size (%d bytes) -- dropped",
                cp.id,
                self._max_size_bytes,
            )
            return ""

        encrypted = self._encrypt_payload(payload_json)

        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO checkpoints "
                "(id, function_name, module, step_name, step_index, payload, timestamp, completed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cp.id,
                    cp.function_name,
                    cp.module,
                    cp.step_name,
                    cp.step_index,
                    encrypted,
                    cp.timestamp.isoformat(),
                    1 if cp.completed else 0,
                ),
            )
        return cp.id

    def get_checkpoint(self, checkpoint_id: str) -> CheckpointState | None:
        """Retrieve a single checkpoint by id."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM checkpoints WHERE id = ?",
                (checkpoint_id,),
            ).fetchone()
        if row is None:
            return None
        data = safe_deserialize(self._decrypt_payload(row["payload"]))
        if isinstance(data, dict):
            return CheckpointState.from_dict(data)
        return None

    def get_latest_checkpoint(
        self,
        function_name: str,
        module: str = "",
    ) -> CheckpointState | None:
        """Return the most recent checkpoint for the given function."""
        query = "SELECT payload FROM checkpoints WHERE function_name = ?"
        params: list[Any] = [function_name]
        if module:
            query += " AND module = ?"
            params.append(module)
        query += " ORDER BY timestamp DESC LIMIT 1"

        with self._lock, self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        if row is None:
            return None
        data = safe_deserialize(self._decrypt_payload(row["payload"]))
        if isinstance(data, dict):
            return CheckpointState.from_dict(data)
        return None

    def list_checkpoints(
        self,
        *,
        function_name: str | None = None,
        limit: int = 50,
    ) -> list[CheckpointState]:
        """Return recent checkpoints, newest first."""
        query = "SELECT payload FROM checkpoints"
        params: list[Any] = []
        if function_name:
            query += " WHERE function_name = ?"
            params.append(function_name)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        checkpoints: list[CheckpointState] = []
        for row in rows:
            data = safe_deserialize(self._decrypt_payload(row["payload"]))
            if isinstance(data, dict):
                checkpoints.append(CheckpointState.from_dict(data))
        return checkpoints

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Delete a single checkpoint."""
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM checkpoints WHERE id = ?", (checkpoint_id,))
            return cur.rowcount > 0

    def clear_checkpoints(self) -> int:
        """Delete all checkpoints.  Returns the number removed."""
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM checkpoints")
            return cur.rowcount

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    def _prune_captures(self, conn: sqlite3.Connection) -> None:
        """Remove the oldest captures when the total exceeds the limit."""
        row = conn.execute("SELECT COUNT(*) AS cnt FROM captures").fetchone()
        count = row["cnt"] if row else 0
        if count <= self._max_captures:
            return
        overflow = count - self._max_captures
        conn.execute(
            "DELETE FROM captures WHERE id IN ("
            "  SELECT id FROM captures ORDER BY timestamp ASC LIMIT ?"
            ")",
            (overflow,),
        )
        logger.debug("Pruned %d oldest capture(s)", overflow)
