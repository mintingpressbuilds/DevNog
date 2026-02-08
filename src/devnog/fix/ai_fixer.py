"""AI-powered fix generator using Claude API."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from devnog.core.models import Finding, FixProposal


@dataclass
class CodeContext:
    """Context gathered for AI fix generation."""

    file_content: str
    file_path: Path
    related_imports: str
    project_structure: str


class AIFixer:
    """Generates fixes using Claude API for complex issues."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514", max_tokens: int = 2000):
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        """Lazy-initialize the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "AI fixes require the anthropic package. "
                    "Install with: pip install devnog[ai]"
                )
        return self._client

    async def generate_fix(self, finding: Finding, context: CodeContext) -> FixProposal | None:
        """Generate an AI-powered fix for a complex issue."""
        prompt = self._build_prompt(finding, context)

        try:
            client = self._get_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            return self._parse_response(response, finding, context)
        except Exception as e:
            return None

    def _build_prompt(self, finding: Finding, context: CodeContext) -> str:
        """Build the prompt for Claude."""
        return f"""You are DevNog's fix engine. Generate a precise code fix.

ISSUE:
  ID: {finding.check_id}
  Category: {finding.category.value}
  Severity: {finding.severity.value}
  Message: {finding.message}
  File: {finding.file}:{finding.line}

SOURCE CODE:
```python
{context.file_content}
```

RELATED FILES:
{context.related_imports}

CONSTRAINTS:
- Produce a minimal, surgical fix. Change as few lines as possible.
- Do not change function signatures or public APIs.
- Maintain backward compatibility.
- Use existing project patterns (same style, same libraries).
- If the fix requires a new dependency, note it explicitly.
- If the fix requires a manual step (env var, config change), note it explicitly.

Respond in this exact format:

DIFF:
```
<unified diff of changes>
```

NEW_CODE:
```python
<the replacement code>
```

ORIGINAL_CODE:
```python
<the original code being replaced>
```

EXPLANATION: <one-line explanation>

MANUAL_STEPS: <comma-separated list of manual steps, or "None">

CONFIDENCE: <high|medium|low>

SIDE_EFFECTS: <comma-separated list of potential side effects, or "None">
"""

    def _parse_response(
        self, response, finding: Finding, context: CodeContext
    ) -> FixProposal | None:
        """Parse Claude's response into a FixProposal."""
        text = response.content[0].text

        # Extract sections
        diff = self._extract_section(text, "DIFF")
        new_code = self._extract_section(text, "NEW_CODE")
        original_code = self._extract_section(text, "ORIGINAL_CODE")
        explanation = self._extract_line(text, "EXPLANATION:")
        manual_steps_raw = self._extract_line(text, "MANUAL_STEPS:")
        confidence = self._extract_line(text, "CONFIDENCE:").lower().strip()
        side_effects_raw = self._extract_line(text, "SIDE_EFFECTS:")

        if not new_code:
            return None

        # Parse manual steps
        manual_steps = []
        if manual_steps_raw and manual_steps_raw.strip().lower() != "none":
            manual_steps = [s.strip() for s in manual_steps_raw.split(",") if s.strip()]

        # Parse side effects
        side_effects = []
        if side_effects_raw and side_effects_raw.strip().lower() != "none":
            side_effects = [s.strip() for s in side_effects_raw.split(",") if s.strip()]

        # Determine confidence
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"

        confidence_score = {"high": 0.85, "medium": 0.60, "low": 0.35}.get(confidence, 0.60)

        return FixProposal(
            finding_id=finding.check_id,
            fix_type="ai_generated",
            description=explanation or f"AI fix for {finding.check_id}",
            diff=diff or "",
            file=finding.file or Path("."),
            line_start=finding.line or 0,
            line_end=finding.end_line or finding.line or 0,
            new_code=new_code,
            original_code=original_code or "",
            manual_steps=manual_steps,
            confidence=confidence,
            confidence_score=confidence_score,
            side_effects=side_effects,
            requires_review=confidence != "high",
        )

    def _extract_section(self, text: str, header: str) -> str:
        """Extract a code section from the response."""
        pattern = rf"{header}:\s*```(?:\w*)\n(.*?)```"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""

    def _extract_line(self, text: str, prefix: str) -> str:
        """Extract a single-line value from the response."""
        for line in text.splitlines():
            if line.strip().startswith(prefix):
                return line.strip()[len(prefix):].strip()
        return ""
