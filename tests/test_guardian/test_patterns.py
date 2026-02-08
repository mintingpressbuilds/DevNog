"""Tests for the FailurePatternDetector (Pro feature)."""

from __future__ import annotations

import time

import pytest

from devnog.guardian.patterns import (
    DetectedPattern,
    FailureEvent,
    FailurePatternDetector,
    PatternKind,
)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _event(
    function_name: str = "func_a",
    error_type: str = "ValueError",
    error_message: str = "something",
    module: str = "mod",
    timestamp: float | None = None,
) -> FailureEvent:
    return FailureEvent(
        function_name=function_name,
        module=module,
        error_type=error_type,
        error_message=error_message,
        timestamp=timestamp if timestamp is not None else time.monotonic(),
    )


# -----------------------------------------------------------------------
# Basic operations
# -----------------------------------------------------------------------

class TestFailurePatternDetectorBasic:
    def test_initial_state(self):
        det = FailurePatternDetector()
        assert det.event_count == 0
        assert det.get_patterns() == []

    def test_record_returns_empty_for_single_event(self):
        det = FailurePatternDetector()
        patterns = det.record(_event())
        assert patterns == []
        assert det.event_count == 1

    def test_clear_resets_state(self):
        det = FailurePatternDetector()
        det.record(_event())
        det.record(_event())
        det.clear()
        assert det.event_count == 0
        assert det.get_patterns() == []


# -----------------------------------------------------------------------
# REPEATED_FUNCTION detection
# -----------------------------------------------------------------------

class TestRepeatedFunctionPattern:
    def test_detects_repeated_function(self):
        det = FailurePatternDetector(repeat_threshold=3)
        now = time.monotonic()

        patterns = []
        for i in range(3):
            p = det.record(
                _event(function_name="buggy_func", timestamp=now + i)
            )
            patterns.extend(p)

        assert len(patterns) == 1
        assert patterns[0].kind == PatternKind.REPEATED_FUNCTION
        assert "buggy_func" in patterns[0].description
        assert patterns[0].count >= 3

    def test_does_not_fire_below_threshold(self):
        det = FailurePatternDetector(repeat_threshold=5)
        now = time.monotonic()

        patterns = []
        for i in range(4):
            p = det.record(
                _event(function_name="buggy_func", timestamp=now + i)
            )
            patterns.extend(p)

        assert all(p.kind != PatternKind.REPEATED_FUNCTION for p in patterns)

    def test_does_not_re_fire_same_function(self):
        det = FailurePatternDetector(repeat_threshold=2)
        now = time.monotonic()

        # First trigger
        det.record(_event(function_name="f", timestamp=now))
        patterns = det.record(_event(function_name="f", timestamp=now + 1))
        assert len(patterns) == 1

        # Additional events should update the existing pattern, not create new.
        patterns = det.record(_event(function_name="f", timestamp=now + 2))
        assert len(patterns) == 0


# -----------------------------------------------------------------------
# SAME_ERROR_TYPE detection
# -----------------------------------------------------------------------

class TestSameErrorTypePattern:
    def test_detects_same_error_across_functions(self):
        det = FailurePatternDetector(error_type_threshold=3)
        now = time.monotonic()

        patterns = []
        for i, fn in enumerate(["func_a", "func_b", "func_c"]):
            p = det.record(
                _event(function_name=fn, error_type="TimeoutError", timestamp=now + i)
            )
            patterns.extend(p)

        same_type = [p for p in patterns if p.kind == PatternKind.SAME_ERROR_TYPE]
        assert len(same_type) == 1
        assert "TimeoutError" in same_type[0].description

    def test_requires_multiple_distinct_functions(self):
        det = FailurePatternDetector(error_type_threshold=3)
        now = time.monotonic()

        patterns = []
        for i in range(5):
            p = det.record(
                _event(
                    function_name="same_func",
                    error_type="TimeoutError",
                    timestamp=now + i,
                )
            )
            patterns.extend(p)

        same_type = [p for p in patterns if p.kind == PatternKind.SAME_ERROR_TYPE]
        assert len(same_type) == 0


# -----------------------------------------------------------------------
# TIME_CORRELATED (burst) detection
# -----------------------------------------------------------------------

class TestTimeCorrelatedPattern:
    def test_detects_burst(self):
        det = FailurePatternDetector(
            burst_threshold=5,
            burst_window_seconds=10.0,
        )
        now = time.monotonic()

        patterns = []
        for i in range(5):
            p = det.record(
                _event(
                    function_name=f"func_{i}",
                    error_type=f"Error{i}",
                    timestamp=now + i * 0.1,
                )
            )
            patterns.extend(p)

        burst = [p for p in patterns if p.kind == PatternKind.TIME_CORRELATED]
        assert len(burst) == 1
        assert "5" in burst[0].description  # "Burst of 5 failures..."

    def test_no_burst_when_spread_out(self):
        det = FailurePatternDetector(
            burst_threshold=5,
            burst_window_seconds=1.0,
        )
        now = time.monotonic()

        patterns = []
        for i in range(5):
            p = det.record(
                _event(
                    function_name=f"func_{i}",
                    error_type=f"Error{i}",
                    # Each event is 2 seconds apart, exceeding the 1s window
                    timestamp=now + i * 2.0,
                )
            )
            patterns.extend(p)

        burst = [p for p in patterns if p.kind == PatternKind.TIME_CORRELATED]
        assert len(burst) == 0


# -----------------------------------------------------------------------
# CASCADE detection
# -----------------------------------------------------------------------

class TestCascadePattern:
    def test_detects_cascade(self):
        det = FailurePatternDetector(
            cascade_window_seconds=5.0,
            cascade_min_functions=3,
        )
        now = time.monotonic()

        patterns = []
        for i, fn in enumerate(["svc_auth", "svc_db", "svc_api"]):
            p = det.record(
                _event(function_name=fn, timestamp=now + i * 0.5)
            )
            patterns.extend(p)

        cascade = [p for p in patterns if p.kind == PatternKind.CASCADE]
        assert len(cascade) == 1
        assert "3 distinct functions" in cascade[0].description

    def test_no_cascade_with_same_function(self):
        det = FailurePatternDetector(
            cascade_window_seconds=5.0,
            cascade_min_functions=3,
        )
        now = time.monotonic()

        patterns = []
        for i in range(5):
            p = det.record(
                _event(function_name="same_func", timestamp=now + i * 0.1)
            )
            patterns.extend(p)

        cascade = [p for p in patterns if p.kind == PatternKind.CASCADE]
        assert len(cascade) == 0


# -----------------------------------------------------------------------
# Eviction
# -----------------------------------------------------------------------

class TestEviction:
    def test_events_outside_window_are_evicted(self):
        det = FailurePatternDetector(window_seconds=10.0)
        now = time.monotonic()

        # Event in the far past (outside window)
        det.record(_event(timestamp=now - 100))
        # Event in the present
        det.record(_event(timestamp=now))

        # After recording the present event, the old one should be evicted.
        assert det.event_count == 1

    def test_max_events_hard_cap(self):
        det = FailurePatternDetector(max_events=10)
        now = time.monotonic()

        for i in range(20):
            det.record(_event(timestamp=now + i * 0.01))

        assert det.event_count <= 10


# -----------------------------------------------------------------------
# Confidence
# -----------------------------------------------------------------------

class TestPatternConfidence:
    def test_repeated_function_confidence_increases(self):
        det = FailurePatternDetector(repeat_threshold=2)
        now = time.monotonic()

        det.record(_event(function_name="f", timestamp=now))
        patterns = det.record(_event(function_name="f", timestamp=now + 1))

        assert len(patterns) == 1
        assert 0.0 < patterns[0].confidence <= 1.0

    def test_confidence_capped_at_1(self):
        det = FailurePatternDetector(repeat_threshold=1)
        now = time.monotonic()

        for i in range(20):
            det.record(_event(function_name="f", timestamp=now + i))

        all_patterns = det.get_patterns()
        for p in all_patterns:
            assert p.confidence <= 1.0


# -----------------------------------------------------------------------
# get_patterns snapshot
# -----------------------------------------------------------------------

class TestGetPatterns:
    def test_returns_snapshot(self):
        det = FailurePatternDetector(repeat_threshold=2)
        now = time.monotonic()

        det.record(_event(function_name="f", timestamp=now))
        det.record(_event(function_name="f", timestamp=now + 1))

        snapshot = det.get_patterns()
        assert len(snapshot) >= 1
        assert all(isinstance(p, DetectedPattern) for p in snapshot)

    def test_mutating_snapshot_does_not_affect_internal_state(self):
        det = FailurePatternDetector(repeat_threshold=2)
        now = time.monotonic()

        det.record(_event(function_name="f", timestamp=now))
        det.record(_event(function_name="f", timestamp=now + 1))

        snapshot = det.get_patterns()
        snapshot.clear()
        # Internal state should be unaffected.
        assert len(det.get_patterns()) >= 1
