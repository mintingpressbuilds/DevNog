"""Pro: Cross-failure pattern detection for Guardian.

Detects recurring and correlated failure patterns so that the healing
engine can apply targeted strategies rather than generic retries.

Requires a Pro or Enterprise license.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Pattern types
# ---------------------------------------------------------------------------

class PatternKind(Enum):
    """Classification of a detected failure pattern."""

    REPEATED_FUNCTION = "repeated_function"
    SAME_ERROR_TYPE = "same_error_type"
    TIME_CORRELATED = "time_correlated"
    CASCADE = "cascade"


@dataclass
class FailureEvent:
    """Lightweight record of a single failure occurrence."""

    function_name: str
    module: str
    error_type: str
    error_message: str
    timestamp: float = field(default_factory=time.monotonic)
    request_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectedPattern:
    """A pattern surfaced by the detector."""

    kind: PatternKind
    description: str
    events: list[FailureEvent] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 – 1.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    count: int = 0


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class FailurePatternDetector:
    """Analyse a stream of :class:`FailureEvent` objects to find patterns.

    **Pro feature** — instantiation is gated by the license manager.

    Thread-safe: all mutations are protected by a lock so that the detector
    can be shared across ASGI worker tasks.

    Detection rules
    ---------------
    * **Repeated function** — the same ``function_name`` fails more than
      *repeat_threshold* times inside *window_seconds*.
    * **Same error type** — the same ``error_type`` appears across
      different functions more than *error_type_threshold* times.
    * **Time-correlated** — a burst of failures (any kind) that exceeds
      *burst_threshold* within *burst_window_seconds*.
    * **Cascade** — multiple *distinct* functions fail in rapid succession
      (within *cascade_window_seconds*), suggesting one failure triggers
      downstream failures.
    """

    def __init__(
        self,
        *,
        window_seconds: float = 600.0,       # 10 min
        repeat_threshold: int = 3,
        error_type_threshold: int = 3,
        burst_threshold: int = 5,
        burst_window_seconds: float = 30.0,
        cascade_window_seconds: float = 5.0,
        cascade_min_functions: int = 3,
        max_events: int = 2000,
    ) -> None:
        self._lock = threading.Lock()

        # tuning knobs
        self.window_seconds = window_seconds
        self.repeat_threshold = repeat_threshold
        self.error_type_threshold = error_type_threshold
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.cascade_window_seconds = cascade_window_seconds
        self.cascade_min_functions = cascade_min_functions
        self.max_events = max_events

        # state
        self._events: list[FailureEvent] = []
        self._by_function: dict[str, list[FailureEvent]] = defaultdict(list)
        self._by_error_type: dict[str, list[FailureEvent]] = defaultdict(list)
        self._detected: list[DetectedPattern] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, event: FailureEvent) -> list[DetectedPattern]:
        """Record a new failure event and return any *newly* detected patterns.

        Returns an empty list most of the time.  A non-empty list means one
        or more patterns crossed their thresholds.
        """
        with self._lock:
            self._events.append(event)
            self._by_function[event.function_name].append(event)
            self._by_error_type[event.error_type].append(event)
            self._evict_old()
            return self._detect(event)

    def get_patterns(self) -> list[DetectedPattern]:
        """Return all currently active patterns (snapshot)."""
        with self._lock:
            return list(self._detected)

    def clear(self) -> None:
        """Reset all state."""
        with self._lock:
            self._events.clear()
            self._by_function.clear()
            self._by_error_type.clear()
            self._detected.clear()

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _evict_old(self) -> None:
        """Drop events outside the window or above the capacity limit."""
        cutoff = time.monotonic() - self.window_seconds
        self._events = [e for e in self._events if e.timestamp >= cutoff]

        # Also prune per-key indices.
        for key in list(self._by_function):
            lst = [e for e in self._by_function[key] if e.timestamp >= cutoff]
            if lst:
                self._by_function[key] = lst
            else:
                del self._by_function[key]

        for key in list(self._by_error_type):
            lst = [e for e in self._by_error_type[key] if e.timestamp >= cutoff]
            if lst:
                self._by_error_type[key] = lst
            else:
                del self._by_error_type[key]

        # Hard cap.
        if len(self._events) > self.max_events:
            excess = len(self._events) - self.max_events
            self._events = self._events[excess:]

        # Expire detected patterns whose events have all aged out.
        self._detected = [
            p for p in self._detected if p.last_seen >= cutoff
        ]

    def _detect(self, latest: FailureEvent) -> list[DetectedPattern]:
        """Run all detectors against the latest event.  Return new patterns."""
        new_patterns: list[DetectedPattern] = []

        p = self._check_repeated_function(latest)
        if p is not None:
            new_patterns.append(p)

        p = self._check_same_error_type(latest)
        if p is not None:
            new_patterns.append(p)

        p = self._check_time_correlated(latest)
        if p is not None:
            new_patterns.append(p)

        p = self._check_cascade(latest)
        if p is not None:
            new_patterns.append(p)

        self._detected.extend(new_patterns)
        return new_patterns

    # -- individual detectors ---------------------------------------------

    def _check_repeated_function(
        self, latest: FailureEvent
    ) -> DetectedPattern | None:
        events = self._by_function.get(latest.function_name, [])
        if len(events) < self.repeat_threshold:
            return None
        # Only fire once per function per window — check if already reported.
        for existing in self._detected:
            if (
                existing.kind is PatternKind.REPEATED_FUNCTION
                and existing.events
                and existing.events[0].function_name == latest.function_name
            ):
                # Update the existing pattern instead.
                existing.last_seen = latest.timestamp
                existing.count = len(events)
                return None

        return DetectedPattern(
            kind=PatternKind.REPEATED_FUNCTION,
            description=(
                f"Function '{latest.function_name}' has failed "
                f"{len(events)} times in the last "
                f"{self.window_seconds:.0f}s"
            ),
            events=list(events),
            confidence=min(1.0, len(events) / (self.repeat_threshold * 2)),
            first_seen=events[0].timestamp,
            last_seen=latest.timestamp,
            count=len(events),
        )

    def _check_same_error_type(
        self, latest: FailureEvent
    ) -> DetectedPattern | None:
        events = self._by_error_type.get(latest.error_type, [])
        # Must span multiple distinct functions.
        functions = {e.function_name for e in events}
        if len(functions) < 2 or len(events) < self.error_type_threshold:
            return None

        for existing in self._detected:
            if (
                existing.kind is PatternKind.SAME_ERROR_TYPE
                and existing.events
                and existing.events[0].error_type == latest.error_type
            ):
                existing.last_seen = latest.timestamp
                existing.count = len(events)
                return None

        return DetectedPattern(
            kind=PatternKind.SAME_ERROR_TYPE,
            description=(
                f"Error type '{latest.error_type}' seen across "
                f"{len(functions)} functions ({len(events)} occurrences)"
            ),
            events=list(events),
            confidence=min(1.0, len(functions) / 5),
            first_seen=events[0].timestamp,
            last_seen=latest.timestamp,
            count=len(events),
        )

    def _check_time_correlated(
        self, latest: FailureEvent
    ) -> DetectedPattern | None:
        cutoff = latest.timestamp - self.burst_window_seconds
        burst = [e for e in self._events if e.timestamp >= cutoff]
        if len(burst) < self.burst_threshold:
            return None

        # Avoid re-reporting the same burst.
        for existing in self._detected:
            if existing.kind is PatternKind.TIME_CORRELATED:
                overlap = latest.timestamp - existing.last_seen
                if overlap < self.burst_window_seconds:
                    existing.last_seen = latest.timestamp
                    existing.count = len(burst)
                    return None

        return DetectedPattern(
            kind=PatternKind.TIME_CORRELATED,
            description=(
                f"Burst of {len(burst)} failures within "
                f"{self.burst_window_seconds:.0f}s"
            ),
            events=list(burst),
            confidence=min(1.0, len(burst) / (self.burst_threshold * 2)),
            first_seen=burst[0].timestamp,
            last_seen=latest.timestamp,
            count=len(burst),
        )

    def _check_cascade(
        self, latest: FailureEvent
    ) -> DetectedPattern | None:
        cutoff = latest.timestamp - self.cascade_window_seconds
        recent = [e for e in self._events if e.timestamp >= cutoff]
        functions = {e.function_name for e in recent}
        if len(functions) < self.cascade_min_functions:
            return None

        for existing in self._detected:
            if existing.kind is PatternKind.CASCADE:
                overlap = latest.timestamp - existing.last_seen
                if overlap < self.cascade_window_seconds:
                    existing.last_seen = latest.timestamp
                    existing.count = len(recent)
                    return None

        return DetectedPattern(
            kind=PatternKind.CASCADE,
            description=(
                f"Cascade: {len(functions)} distinct functions failed "
                f"within {self.cascade_window_seconds:.1f}s"
            ),
            events=list(recent),
            confidence=min(1.0, len(functions) / (self.cascade_min_functions * 2)),
            first_seen=recent[0].timestamp,
            last_seen=latest.timestamp,
            count=len(recent),
        )
