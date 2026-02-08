"""Tests for CaptureStore: save, load, list, delete, encryption, and pruning."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from devnog.capture.models import CheckpointState, FailureCapture
from devnog.capture.store import CaptureStore, DEFAULT_MAX_CAPTURES


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _make_capture(
    *,
    function_name: str = "my_func",
    module: str = "my_module",
    error_type: str = "ValueError",
    error_message: str = "something broke",
    args: list | None = None,
    kwargs: dict | None = None,
) -> FailureCapture:
    return FailureCapture(
        function_name=function_name,
        module=module,
        error_type=error_type,
        error_message=error_message,
        traceback_str="Traceback ...",
        args_snapshot=args or [1, 2],
        kwargs_snapshot=kwargs or {"x": 10},
        local_vars={"a": 1},
        timestamp=datetime.utcnow(),
        file_path="/tmp/test.py",
        line_number=42,
    )


def _make_checkpoint(
    *,
    function_name: str = "pipeline",
    module: str = "my_module",
    step_name: str = "step1",
    step_index: int = 0,
    state: dict | None = None,
    completed: bool = False,
) -> CheckpointState:
    return CheckpointState(
        function_name=function_name,
        module=module,
        step_name=step_name,
        step_index=step_index,
        state=state or {"result": "ok"},
        args_snapshot=[1],
        kwargs_snapshot={"k": "v"},
        timestamp=datetime.utcnow(),
        completed=completed,
    )


# -----------------------------------------------------------------------
# Fixture: CaptureStore backed by a tmp_path
# -----------------------------------------------------------------------

@pytest.fixture()
def store(tmp_path: Path) -> CaptureStore:
    """Return a CaptureStore that writes to a temporary directory."""
    return CaptureStore(project_path=tmp_path, max_captures=50, max_size_bytes=5 * 1024 * 1024)


# -----------------------------------------------------------------------
# Captures -- CRUD
# -----------------------------------------------------------------------

class TestCaptureStoreSaveAndLoad:
    def test_save_and_get_capture(self, store: CaptureStore):
        fc = _make_capture()
        capture_id = store.save_capture(fc)
        assert capture_id != ""

        loaded = store.get_capture(capture_id)
        assert loaded is not None
        assert loaded.function_name == "my_func"
        assert loaded.error_type == "ValueError"
        assert loaded.error_message == "something broke"

    def test_get_nonexistent_returns_none(self, store: CaptureStore):
        assert store.get_capture("nonexistent-id") is None

    def test_save_increments_occurrence_count(self, store: CaptureStore):
        """Saving the same function+error combo should bump the count."""
        fc1 = _make_capture()
        cid1 = store.save_capture(fc1)

        fc2 = _make_capture()
        cid2 = store.save_capture(fc2)

        # Second save updates the existing row rather than inserting.
        assert cid2 == cid1
        loaded = store.get_capture(cid1)
        assert loaded is not None
        assert loaded.occurrence_count == 2

    def test_different_errors_create_separate_captures(self, store: CaptureStore):
        fc1 = _make_capture(error_type="ValueError")
        fc2 = _make_capture(error_type="TypeError")
        cid1 = store.save_capture(fc1)
        cid2 = store.save_capture(fc2)
        assert cid1 != cid2
        assert store.capture_count() == 2


class TestCaptureStoreList:
    def test_list_captures_returns_newest_first(self, store: CaptureStore):
        for i in range(5):
            fc = _make_capture(error_type=f"Error{i}")
            fc.timestamp = datetime.utcnow() + timedelta(seconds=i)
            store.save_capture(fc)

        captures = store.list_captures(limit=10)
        assert len(captures) == 5
        # Newest first
        timestamps = [c.timestamp for c in captures]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_list_with_function_name_filter(self, store: CaptureStore):
        store.save_capture(_make_capture(function_name="alpha", error_type="E1"))
        store.save_capture(_make_capture(function_name="beta", error_type="E2"))

        results = store.list_captures(function_name="alpha")
        assert len(results) == 1
        assert results[0].function_name == "alpha"

    def test_list_respects_limit(self, store: CaptureStore):
        for i in range(10):
            store.save_capture(_make_capture(error_type=f"E{i}"))

        results = store.list_captures(limit=3)
        assert len(results) == 3


class TestCaptureStoreDelete:
    def test_delete_capture(self, store: CaptureStore):
        fc = _make_capture()
        cid = store.save_capture(fc)
        assert store.delete_capture(cid) is True
        assert store.get_capture(cid) is None

    def test_delete_nonexistent_returns_false(self, store: CaptureStore):
        assert store.delete_capture("no-such-id") is False

    def test_clear_captures(self, store: CaptureStore):
        for i in range(5):
            store.save_capture(_make_capture(error_type=f"E{i}"))
        removed = store.clear_captures()
        assert removed == 5
        assert store.capture_count() == 0


class TestCaptureStoreCount:
    def test_initial_count_is_zero(self, store: CaptureStore):
        assert store.capture_count() == 0

    def test_count_after_inserts(self, store: CaptureStore):
        for i in range(3):
            store.save_capture(_make_capture(error_type=f"E{i}"))
        assert store.capture_count() == 3


# -----------------------------------------------------------------------
# Size limit
# -----------------------------------------------------------------------

class TestCaptureStoreSizeLimit:
    def test_oversized_capture_is_dropped(self, tmp_path: Path):
        """A capture exceeding max_size_bytes returns empty string."""
        small_store = CaptureStore(
            project_path=tmp_path, max_captures=10, max_size_bytes=50
        )
        fc = _make_capture(error_message="x" * 10000)
        result = small_store.save_capture(fc)
        assert result == ""
        assert small_store.capture_count() == 0


# -----------------------------------------------------------------------
# Pruning
# -----------------------------------------------------------------------

class TestCaptureStorePruning:
    def test_prunes_oldest_when_limit_exceeded(self, tmp_path: Path):
        """When the max capture count is exceeded, oldest entries are removed."""
        small_store = CaptureStore(
            project_path=tmp_path, max_captures=3, max_size_bytes=5 * 1024 * 1024
        )
        ids = []
        for i in range(5):
            fc = _make_capture(error_type=f"E{i}")
            fc.timestamp = datetime.utcnow() + timedelta(seconds=i)
            cid = small_store.save_capture(fc)
            ids.append(cid)

        assert small_store.capture_count() == 3
        # The two oldest (E0, E1) should have been pruned.
        assert small_store.get_capture(ids[0]) is None
        assert small_store.get_capture(ids[1]) is None


# -----------------------------------------------------------------------
# Checkpoints -- CRUD
# -----------------------------------------------------------------------

class TestCheckpointSaveAndLoad:
    def test_save_and_get_checkpoint(self, store: CaptureStore):
        cp = _make_checkpoint()
        cp_id = store.save_checkpoint(cp)
        assert cp_id != ""

        loaded = store.get_checkpoint(cp_id)
        assert loaded is not None
        assert loaded.function_name == "pipeline"
        assert loaded.step_name == "step1"
        assert loaded.state == {"result": "ok"}

    def test_get_nonexistent_checkpoint_returns_none(self, store: CaptureStore):
        assert store.get_checkpoint("nonexistent") is None

    def test_save_checkpoint_upserts(self, store: CaptureStore):
        """Saving the same checkpoint id replaces the row (INSERT OR REPLACE)."""
        cp = _make_checkpoint()
        cp_id = store.save_checkpoint(cp)

        cp.step_name = "step2"
        store.save_checkpoint(cp)

        loaded = store.get_checkpoint(cp_id)
        assert loaded is not None
        assert loaded.step_name == "step2"


class TestCheckpointList:
    def test_list_checkpoints(self, store: CaptureStore):
        for i in range(4):
            cp = _make_checkpoint(step_name=f"step{i}", step_index=i)
            cp.timestamp = datetime.utcnow() + timedelta(seconds=i)
            store.save_checkpoint(cp)

        cps = store.list_checkpoints(limit=10)
        assert len(cps) == 4

    def test_list_checkpoints_with_function_filter(self, store: CaptureStore):
        store.save_checkpoint(_make_checkpoint(function_name="funcA"))
        store.save_checkpoint(_make_checkpoint(function_name="funcB"))

        results = store.list_checkpoints(function_name="funcA")
        assert len(results) == 1
        assert results[0].function_name == "funcA"


class TestCheckpointLatest:
    def test_get_latest_checkpoint(self, store: CaptureStore):
        cp1 = _make_checkpoint(step_name="early")
        cp1.timestamp = datetime.utcnow() - timedelta(seconds=10)
        store.save_checkpoint(cp1)

        cp2 = _make_checkpoint(step_name="late")
        cp2.timestamp = datetime.utcnow()
        store.save_checkpoint(cp2)

        latest = store.get_latest_checkpoint("pipeline")
        assert latest is not None
        assert latest.step_name == "late"

    def test_get_latest_checkpoint_with_module(self, store: CaptureStore):
        cp = _make_checkpoint(module="some.module")
        store.save_checkpoint(cp)

        result = store.get_latest_checkpoint("pipeline", module="some.module")
        assert result is not None

        result_wrong_module = store.get_latest_checkpoint("pipeline", module="other.module")
        assert result_wrong_module is None

    def test_get_latest_checkpoint_no_match(self, store: CaptureStore):
        assert store.get_latest_checkpoint("no_such_function") is None


class TestCheckpointDeleteAndClear:
    def test_delete_checkpoint(self, store: CaptureStore):
        cp = _make_checkpoint()
        cp_id = store.save_checkpoint(cp)
        assert store.delete_checkpoint(cp_id) is True
        assert store.get_checkpoint(cp_id) is None

    def test_delete_nonexistent_checkpoint(self, store: CaptureStore):
        assert store.delete_checkpoint("no-such-id") is False

    def test_clear_checkpoints(self, store: CaptureStore):
        for i in range(3):
            store.save_checkpoint(_make_checkpoint(step_name=f"s{i}"))
        removed = store.clear_checkpoints()
        assert removed == 3


# -----------------------------------------------------------------------
# Encryption
# -----------------------------------------------------------------------

class TestCaptureStoreEncryption:
    def test_payload_is_encrypted_on_disk(self, tmp_path: Path):
        """With encryption enabled, raw DB blobs should not contain plaintext."""
        store = CaptureStore(project_path=tmp_path)

        fc = _make_capture(error_message="unique_sentinel_string_12345")
        cid = store.save_capture(fc)
        assert cid != ""

        # Read the raw blob from SQLite directly.
        db_path = tmp_path / ".devnog" / "captures.db"
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT payload FROM captures WHERE id = ?", (cid,)
        ).fetchone()
        conn.close()

        assert row is not None
        raw_blob: bytes = row[0]
        # The plaintext sentinel should NOT appear in the encrypted blob.
        assert b"unique_sentinel_string_12345" not in raw_blob

    def test_unencrypted_store(self, tmp_path: Path):
        """With encryption disabled, plaintext is stored."""
        # Write a devnog.toml that disables encryption.
        (tmp_path / "devnog.toml").write_text(
            "[capture]\nencrypt = false\n"
        )
        store = CaptureStore(project_path=tmp_path)

        fc = _make_capture(error_message="visible_plaintext_678")
        cid = store.save_capture(fc)
        assert cid != ""

        db_path = tmp_path / ".devnog" / "captures.db"
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT payload FROM captures WHERE id = ?", (cid,)
        ).fetchone()
        conn.close()

        raw_blob: bytes = row[0]
        # Without encryption, the payload is plain UTF-8 JSON.
        assert b"visible_plaintext_678" in raw_blob


# -----------------------------------------------------------------------
# Checkpoint oversized
# -----------------------------------------------------------------------

class TestCheckpointSizeLimit:
    def test_oversized_checkpoint_is_dropped(self, tmp_path: Path):
        small_store = CaptureStore(
            project_path=tmp_path, max_captures=10, max_size_bytes=50
        )
        cp = _make_checkpoint(state={"big": "y" * 10000})
        result = small_store.save_checkpoint(cp)
        assert result == ""
