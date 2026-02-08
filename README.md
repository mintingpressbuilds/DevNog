# DevNog — Developer's Bulletproofing Toolkit

**The tool belt that makes shipping without it feel reckless.**

DevNog is a Python CLI + localhost dashboard + lightweight SDK that makes any codebase bulletproof. It doesn't just find problems — it fixes them. One scan, one click, one fix.

```bash
pip install devnog
```

No accounts. No hosting. No cloud. Everything runs locally.

## Quick Start

```bash
# Install
pip install devnog

# Scan your project
cd your-project
devnog scan

# Fix all safe issues
devnog fix --all

# Open interactive dashboard
devnog dashboard
```

Under 60 seconds from install to first fixes applied.

## The Core Experience

```
devnog scan -> see problems -> devnog fix -> score goes up -> repeat until green
```

Every issue has a fix. DevNog never reports a problem without offering a solution:

- **Rule-based fixes** (instant, no API key): For common patterns where the fix is deterministic
- **AI-powered fixes** (requires `ANTHROPIC_API_KEY`): For complex issues using Claude

## Features

### Scanner (`devnog scan`)

AST-based analysis of your Python codebase. 38 built-in checks across 4 categories:

| Category | Checks | What It Finds |
|----------|--------|---------------|
| **Security** | SEC-001 to SEC-012 | Hardcoded secrets, SQL injection, eval(), weak hashing, and more |
| **Code Quality** | CQ-001 to CQ-010 | Long functions, deep nesting, unused imports, duplicate code |
| **Error Handling** | ERR-001 to ERR-008 | Bare except, silent errors, missing timeouts, unhandled I/O |
| **Dependencies** | DEP-001 to DEP-008 | Known CVEs, unpinned deps, unused packages |

```bash
devnog scan                        # Scan current directory
devnog scan ./src                  # Scan specific directory
devnog scan project.zip            # Scan a zip file
devnog scan https://github.com/user/repo  # Scan a GitHub repo
devnog scan --fail-under 70        # CI mode: fail if score below threshold
devnog scan --export json          # Export report as JSON
```

### Fix Engine (`devnog fix`)

The heart of DevNog. Generates and applies fixes for every issue found.

```bash
devnog fix SEC-001                 # Fix a specific issue
devnog fix SEC-001 --preview       # Preview without applying
devnog fix --all                   # Fix all auto-fixable issues
devnog fix --category security     # Fix all security issues
devnog fix ERR-004 --ai            # Use AI for complex fix
devnog undo SEC-001                # Undo a specific fix
devnog undo --last                 # Undo all fixes from last session
```

### QA Gate (`devnog qa`)

Production readiness validation. 25 checks covering timeouts, infrastructure, resilience, and more.

```bash
devnog qa                          # Full readiness check
devnog qa --fix                    # Auto-fix readiness gaps
devnog qa --strict                 # CI mode: fail if not ready
```

### Guardian (Runtime Protection)

Lightweight SDK that captures runtime failures with full context.

```python
from devnog import guard, healable, capture

# Web apps (FastAPI/Starlette)
app = FastAPI()
guard(app)

# Protect specific functions
@healable(retries=3, backoff=True, fallback="skip")
async def call_external_api(payload):
    response = await httpx.post(url, json=payload)
    return response.json()

# Lightweight capture
@capture
def risky_calculation(data):
    return sum(d / normalize(d) for d in data)
```

### Dashboard

Visual localhost web UI with clickable [FIX] buttons.

```bash
devnog dashboard
# Opens http://localhost:7654
```

## Configuration

Create `devnog.toml` in your project root (optional -- everything has sensible defaults):

```toml
[scan]
fail_under = 70
categories = ["code_quality", "security", "error_handling", "dependencies"]

[scan.code_quality]
max_function_length = 50
max_complexity = 10

[fix]
backup_before_fix = true

[dashboard]
port = 7654
```

## Tiers

| Tier | Price | What's Included |
|------|-------|-----------------|
| **Free** | $0 forever | Scanner, all 38 checks, rule-based fixes, QA Gate, observe-only Guardian, dashboard |
| **Pro** | $15-20/month | Everything Free + Guardian auto-healing, pattern detection, healing audit log |
| **Enterprise** | $50-100/seat/month | Everything Pro + enforced team config, CI/CD scan diffs, historical trending, compliance reports |

Set `DEVNOG_LICENSE_KEY` environment variable or save to `.devnog/license.key`.

## AI-Powered Fixes

Set `ANTHROPIC_API_KEY` for AI-powered fixes on complex issues:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
devnog fix SEC-002 --ai
```

Install the AI optional dependency:

```bash
pip install devnog[ai]
```

## Safety

- DevNog **never modifies code** without showing you the diff first and asking for confirmation
- All fixes are **reversible** via `devnog undo`
- **Backups** saved to `.devnog/backups/` before every fix
- First-run **preview mode** shows changes before applying

## Dependencies

Only 3 required dependencies:

- `click` -- CLI framework
- `rich` -- Terminal formatting
- `cryptography` -- Fernet encryption for captures

Optional:
- `anthropic` -- AI-powered fixes (`pip install devnog[ai]`)
- `starlette` -- Guardian ASGI middleware (`pip install devnog[guardian]`)
- `reportlab` -- PDF compliance reports (`pip install devnog[enterprise]`)

## License

MIT
