"""Fix Engine data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class FixProposalConfidence:
    """Confidence assessment for a fix proposal."""

    level: str  # "high", "medium", "low"
    score: float  # 0.0 - 1.0
    reason: str
    side_effects: list[str] = field(default_factory=list)
    review_required: bool = False


@dataclass
class UndoRecord:
    """Record for undoing a fix."""

    finding_id: str
    file: Path
    original_content: str
    fixed_content: str
    applied_at: datetime = field(default_factory=datetime.now)
    description: str = ""
