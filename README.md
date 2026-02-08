[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# DevNog — Developer's Bulletproofing Toolkit

**One scan. One click. One fix. Ship with confidence.**

DevNog is a Python CLI + localhost dashboard + lightweight SDK that makes any codebase bulletproof. It doesn't just find problems — it fixes them.

```bash
pip install devnog
```

No accounts. No hosting. No cloud. Everything runs locally.

---

## Quick Start (under 60 seconds)

```bash
# Install
pip install devnog

# Scan your project
cd your-project
devnog scan

# See the report → fix everything safe → score goes up
devnog fix --all

# Rescan to see your new score
devnog scan
```

That's it. Your codebase just got safer.

---

## All CLI Commands

### `devnog scan` — Find every issue

```bash
devnog scan                        # Scan current directory
devnog scan ./src                  # Scan specific directory
devnog scan project.zip            # Scan a zip file
devnog scan https://github.com/user/repo  # Scan a GitHub repo
devnog scan --fail-under 70        # CI mode: fail if score below threshold
devnog scan --export json          # Export report as JSON
devnog scan --export html          # Export report as HTML
devnog scan --only security        # Scan only specific categories
devnog scan --fix                  # Scan and auto-fix in one step
devnog scan --dashboard            # Scan and open dashboard
```

38 built-in checks across 4 categories:

| Category | Checks | What It Finds |
|----------|--------|---------------|
| **Security** | SEC-001 to SEC-012 | Hardcoded secrets, SQL injection, eval(), weak hashing, open CORS, DEBUG=True, subprocess shell=True |
| **Code Quality** | CQ-001 to CQ-010 | Long functions, deep nesting, unused imports, duplicate code, missing type hints, star imports, dead code |
| **Error Handling** | ERR-001 to ERR-008 | Bare except, silent errors, missing timeouts, unhandled I/O, no global handler |
| **Dependencies** | DEP-001 to DEP-008 | Known CVEs, abandoned packages, unpinned deps, unused packages, outdated versions |

### `devnog fix` — Fix every issue

```bash
devnog fix SEC-001                 # Fix a specific issue
devnog fix SEC-001 --preview       # Preview without applying
devnog fix --all                   # Fix all auto-fixable issues
devnog fix --all -y                # Fix all without confirmation
devnog fix --category security     # Fix all security issues
devnog fix ERR-004 --ai            # Use AI for complex fix (requires ANTHROPIC_API_KEY)
devnog fix --target ./src          # Fix issues in specific directory
```

Every fix shows a diff before applying. All fixes are reversible.

### `devnog undo` — Reverse any fix

```bash
devnog undo SEC-001                # Undo a specific fix
devnog undo --last                 # Undo all fixes from last session
devnog undo --list                 # List all undoable fixes
```

### `devnog qa` — Validate production readiness

```bash
devnog qa                          # Full readiness check (25 checks)
devnog qa ./src                    # Check specific directory
devnog qa --fix                    # Auto-fix readiness gaps
devnog qa --strict                 # CI mode: fail if not ready
```

Checks what tests don't cover: timeouts, retry logic, circuit breakers, transaction handling, structured logging, and more.

### `devnog dashboard` — Visual web UI

```bash
devnog dashboard                   # Opens http://localhost:7654
devnog dashboard --port 8080       # Custom port
devnog dashboard --no-open         # Start without opening browser
```

The dashboard provides:
- **Report Card** tab — Overall score with category breakdown, clickable [FIX] buttons on every issue
- **QA Gate** tab — Production readiness verdict (PASS / CONDITIONAL PASS / FAIL)
- **Runtime** tab — Captured failures from Guardian decorators
- **History** tab — Fix history with [UNDO] buttons
- **Fix modal** — Diff view with confidence indicator, side effects, and manual steps
- **Fix All** button — One click to apply all safe fixes
- **URL scanner** — Paste a GitHub URL to scan any public repo

### `devnog guardian` — Runtime protection status

```bash
devnog guardian                    # Show Guardian status
devnog guardian --status           # Same as above
devnog guardian --audit            # Show healing audit log (Pro)
devnog guardian --report           # Show runtime failure report
```

### `devnog history` — Historical trending (Enterprise)

```bash
devnog history                     # Show score history
devnog history --days 30           # Last 30 days
devnog history --json              # JSON output
```

### `devnog compliance` — Compliance reports (Enterprise)

```bash
devnog compliance                         # Generate OWASP Top 10 report
devnog compliance --framework soc2        # SOC2 compliance report
devnog compliance --export pdf            # Export as PDF
```

---

## Decorator Usage

### `@capture` — Lightweight failure capture

```python
from devnog import capture

@capture
def risky_calculation(data):
    return sum(d / normalize(d) for d in data)
```

When `risky_calculation` fails, DevNog saves a complete snapshot — args, local variables, stack trace, timestamp — to `.devnog/captures.db`. Sensitive data is automatically redacted.

### `@checkpoint` — Resume from last successful step

```python
from devnog import checkpoint

@checkpoint
def long_pipeline(data, _ckpt=None):
    step1_result = expensive_step_1(data)
    _ckpt.save("step1", {"result": step1_result})

    step2_result = expensive_step_2(step1_result)
    _ckpt.save("step2", {"result": step2_result})

    return step2_result
```

If the function fails mid-way, DevNog can replay from the last checkpoint. Accept `_ckpt` as a parameter to save intermediate state.

### `@healable` — Self-healing functions (Pro)

```python
from devnog import healable

@healable(retries=3, backoff=True, fallback="skip")
async def call_external_api(payload):
    response = await httpx.post(url, json=payload)
    return response.json()
```

On **Free tier**, `@healable` captures failures but re-raises them (observe-only mode).
On **Pro tier**, it adds retry with exponential backoff, fallback strategies, and pattern detection.

---

## Guardian Setup

### FastAPI / Starlette

```python
from fastapi import FastAPI
from devnog import guard

app = FastAPI()
guard(app)  # Adds ASGI middleware for request failure capture
```

### Context manager

```python
from devnog import guardian_context

async with guardian_context():
    await do_something_risky()
```

### Configuration

```python
from devnog import guardian_config

guardian_config(
    capture_args=True,
    capture_locals=True,
    max_captures=1000,
    redact_patterns=["password", "token", "secret"],
)
```

---

## Configuration

Create `devnog.toml` in your project root. Everything is optional — sensible defaults are built in:

```toml
[scan]
fail_under = 70                    # CI threshold
categories = ["code_quality", "security", "error_handling", "dependencies"]
exclude = ["tests/", "migrations/", "venv/"]

[scan.code_quality]
max_function_length = 75           # Lines per function
max_nesting_depth = 5              # Max nesting levels
max_complexity = 15                # Cyclomatic complexity

[fix]
backup_before_fix = true           # Save backups to .devnog/backups/

[dashboard]
port = 7654

[guardian]
capture_args = true
capture_locals = true
redact_patterns = ["password", "token", "secret", "key", "auth"]
```

---

## Tiers

| Tier | Price | What's Included |
|------|-------|-----------------|
| **Free** | $0 forever | Scanner (38 checks), rule-based fixes, QA Gate (25 checks), observe-only Guardian, capture decorators, dashboard |
| **Pro** | Coming soon | Everything Free + Guardian auto-healing, pattern detection, healing audit log, `@healable` retry/backoff |
| **Enterprise** | Coming soon | Everything Pro + enforced team config, CI/CD scan diffs, historical trending, OWASP/SOC2 compliance reports |

Set your license key:

```bash
export DEVNOG_LICENSE_KEY="your-key-here"
# Or save to .devnog/license.key
```

---

## AI-Powered Fixes

For complex issues that can't be fixed by rules alone, DevNog uses Claude:

```bash
pip install devnog[ai]
export ANTHROPIC_API_KEY="sk-ant-..."
devnog fix SEC-002 --ai
```

AI fixes include confidence scores, side effect warnings, and manual follow-up steps.

---

## Safety

- DevNog **never modifies code** without showing you the diff first
- All fixes are **reversible** via `devnog undo`
- **Backups** saved to `.devnog/backups/` before every fix
- First time running fixes? DevNog shows **preview-only mode** with no changes applied
- The `.devnog/` directory is auto-added to `.gitignore`

---

## Dependencies

Only 3 required dependencies:

- `click` — CLI framework
- `rich` — Terminal formatting
- `cryptography` — Fernet encryption for capture storage

Optional extras:

```bash
pip install devnog[ai]          # anthropic — AI-powered fixes
pip install devnog[guardian]     # starlette — ASGI middleware
pip install devnog[enterprise]  # reportlab — PDF compliance reports
pip install devnog[all]         # Everything
```

---

## DevNog Pro — Coming Soon

Auto-healing runtime protection. Pattern detection across failures. Full healing audit trail.

Sign up for early access: https://devnog.dev/pro

---

## License

MIT License. See [LICENSE](LICENSE) for details.
