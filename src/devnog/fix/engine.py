"""Fix Engine — orchestrates fix generation and application."""

from __future__ import annotations

import os
from pathlib import Path

from devnog.core.config import DevNogConfig, load_config
from devnog.core.models import Finding, FixProposal, FixResult, FixType
from devnog.fix.ai_fixer import AIFixer, CodeContext
from devnog.fix.applier import FixApplier
from devnog.fix.rule_fixer import RuleBasedFixer
from devnog.fix.undo import UndoManager


class FixEngine:
    """Core engine that generates and applies fixes."""

    def __init__(
        self,
        project_path: Path | None = None,
        config: DevNogConfig | None = None,
        api_key: str | None = None,
    ):
        self.project_path = (project_path or Path.cwd()).resolve()
        self.config = config or load_config(self.project_path)
        self.rule_fixer = RuleBasedFixer()
        self.applier = FixApplier(self.project_path)
        self.undo_manager = UndoManager(self.project_path)

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.ai_fixer = (
            AIFixer(
                api_key=key,
                model=self.config.fix.ai_model,
                max_tokens=self.config.fix.ai_max_tokens,
            )
            if key
            else None
        )

    def generate_fix(self, finding: Finding) -> FixProposal | None:
        """Generate a fix for an issue. Tries rule-based first, then AI."""
        # Read the source file for context
        source = ""
        if finding.file:
            file_path = self._resolve_file(finding.file)
            if file_path.exists():
                source = file_path.read_text(errors="ignore")

        # Try rule-based first
        proposal = self.rule_fixer.try_fix(finding, source)
        if proposal:
            return proposal

        # AI fixes not available in synchronous mode — return None
        # (AI fixes are generated via generate_fix_async)
        return None

    async def generate_fix_async(self, finding: Finding) -> FixProposal | None:
        """Generate a fix, including AI-powered if available."""
        # Try rule-based first
        source = ""
        if finding.file:
            file_path = self._resolve_file(finding.file)
            if file_path.exists():
                source = file_path.read_text(errors="ignore")

        proposal = self.rule_fixer.try_fix(finding, source)
        if proposal:
            return proposal

        # Try AI if available
        if self.ai_fixer and finding.fix_type == FixType.AI_GENERATED:
            context = self._gather_context(finding)
            return await self.ai_fixer.generate_fix(finding, context)

        return None

    def apply_fix(self, proposal: FixProposal) -> FixResult:
        """Apply a fix to the source file."""
        return self.applier.apply(proposal)

    def apply_all_safe(self, findings: list[Finding]) -> list[FixResult]:
        """Apply all rule-based fixes at once."""
        results = []
        for finding in findings:
            if finding.fix_type != FixType.RULE_BASED:
                continue
            proposal = self.generate_fix(finding)
            if proposal and not proposal.requires_review:
                result = self.apply_fix(proposal)
                results.append(result)
        return results

    def undo_fix(self, finding_id: str) -> FixResult:
        """Undo a previously applied fix."""
        return self.undo_manager.undo(finding_id)

    def undo_last(self) -> list[FixResult]:
        """Undo all fixes from the last session."""
        return self.undo_manager.undo_last_session()

    def list_undoable(self):
        """List all undoable fixes."""
        return self.undo_manager.list_undoable()

    def _resolve_file(self, file: Path) -> Path:
        """Resolve possibly relative file path."""
        if file.is_absolute():
            return file
        return self.project_path / file

    def _gather_context(self, finding: Finding) -> CodeContext:
        """Gather code context for AI fix generation."""
        source = ""
        imports = ""
        structure = ""

        if finding.file:
            file_path = self._resolve_file(finding.file)
            if file_path.exists():
                source = file_path.read_text(errors="ignore")
                # Extract imports for context
                import_lines = [
                    l for l in source.splitlines()
                    if l.strip().startswith("import ") or l.strip().startswith("from ")
                ]
                imports = "\n".join(import_lines)

        return CodeContext(
            file_content=source,
            file_path=finding.file or Path("."),
            related_imports=imports,
            project_structure=structure,
        )
