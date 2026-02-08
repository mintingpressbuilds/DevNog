# CLAUDE.md — Contributor Guide for DevNog

## Project Overview

DevNog is a Python CLI + localhost dashboard + lightweight SDK for code analysis and fixing. It scans Python codebases, finds issues, and generates fixes.

## Project Structure

```
src/devnog/
├── __init__.py              # Public API: checkpoint, healable, capture, guard, guardian_context, guardian_config
├── _version.py              # Version string (0.1.0)
├── core/                    # Shared utilities
│   ├── models.py            # Data models: Finding, ScanReport, FixProposal, QAVerdict, etc.
│   ├── config.py            # DevNogConfig, load_config(), devnog.toml parsing
│   ├── license.py           # Tier enum, LicenseManager, tier gating
│   ├── crypto.py            # Fernet encryption for captures
│   ├── output.py            # Rich terminal formatting (print_scan_report, etc.)
│   └── input_resolver.py    # Resolve directory/zip/GitHub URL inputs
├── scanner/                 # Static analysis engine
│   ├── engine.py            # Scanner orchestrator
│   ├── scoring.py           # Weighted scoring algorithm
│   └── checks/              # All 38 scanner checks
│       ├── base.py          # BaseCheck and DependencyCheck ABCs
│       ├── code_quality.py  # CQ-001 through CQ-010
│       ├── security.py      # SEC-001 through SEC-012
│       ├── error_handling.py # ERR-001 through ERR-008
│       └── dependencies.py  # DEP-001 through DEP-008
├── fix/                     # Fix engine
│   ├── engine.py            # FixEngine orchestrator
│   ├── rule_fixer.py        # 13 rule-based fix handlers
│   ├── ai_fixer.py          # Claude-powered fixes
│   ├── applier.py           # Apply fixes with backup
│   ├── undo.py              # UndoManager
│   └── models.py            # FixProposalConfidence, UndoRecord
├── qa/                      # QA Gate (production readiness)
│   ├── engine.py            # QAGate orchestrator
│   └── checks/              # 25 QA checks (QA-001 through QA-025)
│       ├── base.py          # QACheck ABC
│       ├── error_handling.py # QA-001 to QA-003
│       ├── timeouts.py      # QA-004 to QA-006
│       ├── infrastructure.py # QA-007 to QA-011
│       ├── data_safety.py   # QA-012 to QA-013
│       ├── config.py        # QA-014 to QA-016
│       ├── resilience.py    # QA-017 to QA-019
│       ├── performance.py   # QA-020 to QA-021
│       └── observability.py # QA-022 to QA-025
├── capture/                 # Failure capture/replay
│   ├── decorators.py        # @checkpoint, @healable, @capture
│   ├── models.py            # FailureCapture, CheckpointState
│   ├── serializer.py        # Safe serialization + redaction
│   ├── store.py             # Encrypted SQLite capture store
│   └── replayer.py          # Replay from checkpoint
├── guardian/                # Runtime protection
│   ├── middleware.py        # ASGI middleware + guard()
│   ├── context.py           # guardian_context async context manager
│   ├── config.py            # GuardianConfig
│   ├── patterns.py          # FailurePatternDetector (Pro)
│   └── audit.py             # HealingAuditLog (Pro)
├── dashboard/               # Localhost web dashboard
│   └── server.py            # HTTP server with embedded HTML SPA
├── enterprise/              # Enterprise features
│   ├── team_config.py       # TeamConfigEnforcer
│   ├── ci_gate.py           # CIScanDiff for CI/CD
│   ├── trending.py          # HistoryTracker (SQLite)
│   └── compliance.py        # OWASP/SOC2 compliance reports
└── cli/                     # Click CLI commands
    ├── main.py              # CLI entry point (click.Group)
    ├── scan_cmd.py          # devnog scan
    ├── fix_cmd.py           # devnog fix
    ├── qa_cmd.py            # devnog qa
    ├── dashboard_cmd.py     # devnog dashboard
    ├── guardian_cmd.py      # devnog guardian
    ├── undo_cmd.py          # devnog undo
    ├── history_cmd.py       # devnog history (Enterprise)
    └── compliance_cmd.py    # devnog compliance (Enterprise)
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run a specific test module
python -m pytest tests/test_scanner/test_security.py -v

# Run tests for a specific check
python -m pytest tests/test_scanner/test_code_quality.py::TestCQ001FunctionTooLong -v

# Run with coverage
python -m pytest tests/ --cov=devnog --cov-report=term-missing
```

## How to Add a New Scanner Check

1. **Choose an ID** following the pattern: `{CATEGORY}-{NNN}` (e.g., `SEC-013`, `CQ-011`)

2. **Create the check class** in the appropriate file under `src/devnog/scanner/checks/`:

```python
class SEC013NewCheck(BaseCheck):
    """Detect the new security issue."""

    check_id = "SEC-013"
    category = Category.SECURITY
    severity = Severity.WARNING       # CRITICAL, WARNING, or INFO
    fix_type = FixType.RULE_BASED     # RULE_BASED, AI_GENERATED, or MANUAL
    description = "Description of what this detects"

    def run(self, file_path: Path, source: str, tree: ast.Module) -> list[Finding]:
        findings = []
        # Walk the AST and look for the pattern
        for node in ast.walk(tree):
            if self._is_problematic(node):
                findings.append(self._make_finding(
                    message="Human-readable description of the issue",
                    file_path=file_path,
                    line=node.lineno,
                    suggestion="How to fix this",
                ))
        return findings
```

3. **Register the check** in `src/devnog/scanner/checks/__init__.py`:

```python
from devnog.scanner.checks.security import SEC013NewCheck

ALL_CHECKS: list[type] = [
    # ... existing checks ...
    SEC013NewCheck,
]
```

4. **Add a rule-based fix** (optional) in `src/devnog/fix/rule_fixer.py`:

```python
# In the __init__ method, add to self._handlers:
self._handlers["SEC-013"] = self._fix_sec013

def _fix_sec013(self, finding: Finding) -> FixProposal | None:
    # Generate the fix
    ...
```

5. **Write tests** in `tests/test_scanner/test_security.py`:

```python
class TestSEC013NewCheck:
    def test_detects_issue(self, tmp_path):
        code = '''problematic code here'''
        # ... test that it produces findings

    def test_clean_code(self, tmp_path):
        code = '''clean code here'''
        # ... test that it produces no findings
```

6. **Run the tests**:

```bash
python -m pytest tests/test_scanner/test_security.py::TestSEC013NewCheck -v
```

## Key Design Decisions

- **AST-only analysis**: All checks use Python's `ast` module. No code execution.
- **No external services**: Everything runs locally. No accounts or cloud dependencies.
- **Three required deps**: click, rich, cryptography. Everything else is optional.
- **Tier gating**: Use `LicenseManager.require_pro()` / `require_enterprise()` for gated features.
- **Weighted scoring**: security 25%, error_handling 25%, code_quality 20%, dependencies 15%, test_coverage 15%.

## Common Development Tasks

```bash
# Install in development mode
pip install -e ".[dev]"

# Run the CLI locally
devnog scan examples/sample_project/

# Run DevNog on itself
devnog scan src/

# Start dashboard for testing
devnog dashboard --no-open --port 7654
```
