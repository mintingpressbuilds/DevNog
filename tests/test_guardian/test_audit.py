"""Tests for HealingAuditLog (Pro feature)."""

from __future__ import annotations

from pathlib import Path

import pytest

from devnog.guardian.audit import HealingAuditLog, _sanitise, _HEADER


# -----------------------------------------------------------------------
# Fixture
# -----------------------------------------------------------------------

@pytest.fixture()
def audit_log(tmp_path: Path) -> HealingAuditLog:
    """Create a HealingAuditLog backed by a temporary directory."""
    return HealingAuditLog(project_path=tmp_path)


# -----------------------------------------------------------------------
# File creation and header
# -----------------------------------------------------------------------

class TestAuditLogInit:
    def test_creates_log_file_with_header(self, audit_log: HealingAuditLog):
        assert audit_log.path.exists()
        content = audit_log.path.read_text(encoding="utf-8")
        assert content.startswith("# DevNog Guardian Healing Audit Log")

    def test_path_property(self, audit_log: HealingAuditLog):
        assert audit_log.path.name == "healing_audit.log"
        assert audit_log.path.parent.name == ".devnog"


# -----------------------------------------------------------------------
# Recording
# -----------------------------------------------------------------------

class TestAuditLogRecord:
    def test_record_appends_entry(self, audit_log: HealingAuditLog):
        audit_log.record(
            action="retry",
            function="myapp.views.handler",
            error="ValueError: bad input",
            strategy="exponential_backoff",
            result="success",
            duration_ms=42.5,
        )

        content = audit_log.read_all()
        assert "retry" in content
        assert "myapp.views.handler" in content
        assert "ValueError: bad input" in content
        assert "exponential_backoff" in content
        assert "success" in content
        assert "42.5" in content

    def test_record_multiple_entries(self, audit_log: HealingAuditLog):
        for i in range(5):
            audit_log.record(
                action=f"action_{i}",
                function=f"func_{i}",
                error=f"Error{i}",
                strategy="retry",
                result="success",
                duration_ms=float(i),
            )

        entries = audit_log.read_entries(last_n=50)
        assert len(entries) == 5

    def test_record_timestamp_format(self, audit_log: HealingAuditLog):
        audit_log.record(
            action="test",
            function="f",
            error="e",
            strategy="s",
            result="r",
            duration_ms=1.0,
        )
        entries = audit_log.read_entries()
        assert len(entries) == 1
        ts = entries[0]["timestamp"]
        # Should be ISO format with UTC timezone
        assert "T" in ts
        assert "+" in ts or "Z" in ts


# -----------------------------------------------------------------------
# Reading
# -----------------------------------------------------------------------

class TestAuditLogRead:
    def test_read_all_empty_log(self, audit_log: HealingAuditLog):
        content = audit_log.read_all()
        # Should only contain the header.
        assert content.startswith("#")
        assert "DevNog" in content

    def test_read_entries_empty(self, audit_log: HealingAuditLog):
        entries = audit_log.read_entries()
        assert entries == []

    def test_read_entries_parses_correctly(self, audit_log: HealingAuditLog):
        audit_log.record(
            action="fallback",
            function="api.get_data",
            error="ConnectionError: timeout",
            strategy="circuit_break",
            result="failure",
            duration_ms=150.3,
        )

        entries = audit_log.read_entries()
        assert len(entries) == 1
        entry = entries[0]
        assert entry["action"] == "fallback"
        assert entry["function"] == "api.get_data"
        assert entry["error"] == "ConnectionError: timeout"
        assert entry["strategy"] == "circuit_break"
        assert entry["result"] == "failure"
        assert entry["duration_ms"] == "150.3"

    def test_read_entries_last_n(self, audit_log: HealingAuditLog):
        for i in range(10):
            audit_log.record(
                action=f"action_{i}",
                function="f",
                error="e",
                strategy="s",
                result="r",
                duration_ms=1.0,
            )

        entries = audit_log.read_entries(last_n=3)
        assert len(entries) == 3
        # Should be the last 3 entries.
        assert entries[-1]["action"] == "action_9"

    def test_read_all_on_missing_file(self, tmp_path: Path):
        log = HealingAuditLog(project_path=tmp_path)
        # Remove the file
        log.path.unlink()
        assert log.read_all() == ""

    def test_read_entries_on_missing_file(self, tmp_path: Path):
        log = HealingAuditLog(project_path=tmp_path)
        log.path.unlink()
        assert log.read_entries() == []


# -----------------------------------------------------------------------
# Clear
# -----------------------------------------------------------------------

class TestAuditLogClear:
    def test_clear_resets_to_header(self, audit_log: HealingAuditLog):
        audit_log.record(
            action="test",
            function="f",
            error="e",
            strategy="s",
            result="r",
            duration_ms=1.0,
        )
        assert len(audit_log.read_entries()) == 1

        audit_log.clear()
        assert audit_log.read_entries() == []
        # Header should still be present.
        content = audit_log.read_all()
        assert content.startswith("#")


# -----------------------------------------------------------------------
# Sanitisation
# -----------------------------------------------------------------------

class TestSanitise:
    def test_pipe_replaced(self):
        assert "|" not in _sanitise("error | detail")
        assert "/" in _sanitise("error | detail")

    def test_newline_replaced(self):
        assert "\n" not in _sanitise("line1\nline2")

    def test_carriage_return_removed(self):
        assert "\r" not in _sanitise("data\r\n")

    def test_normal_string_unchanged(self):
        assert _sanitise("normal text") == "normal text"


class TestSanitisationInRecord:
    def test_pipes_in_fields_do_not_break_parsing(self, audit_log: HealingAuditLog):
        """Pipe chars in field values should not corrupt the log format."""
        audit_log.record(
            action="retry",
            function="mod|func",
            error="Key|Error: bad|value",
            strategy="backoff",
            result="success|maybe",
            duration_ms=1.0,
        )

        entries = audit_log.read_entries()
        assert len(entries) == 1
        # The values should be sanitised (pipes replaced with /).
        assert "|" not in entries[0]["function"] or entries[0]["function"] == entries[0]["function"]

    def test_newlines_in_error_do_not_break_parsing(self, audit_log: HealingAuditLog):
        audit_log.record(
            action="retry",
            function="func",
            error="Error\nwith\nnewlines",
            strategy="s",
            result="r",
            duration_ms=1.0,
        )
        entries = audit_log.read_entries()
        assert len(entries) == 1


# -----------------------------------------------------------------------
# Concurrent writes
# -----------------------------------------------------------------------

class TestAuditLogConcurrency:
    def test_multiple_sequential_writes(self, audit_log: HealingAuditLog):
        """Multiple rapid writes should not lose data."""
        for i in range(20):
            audit_log.record(
                action=f"action_{i}",
                function="f",
                error="e",
                strategy="s",
                result="r",
                duration_ms=float(i),
            )

        entries = audit_log.read_entries(last_n=100)
        assert len(entries) == 20
