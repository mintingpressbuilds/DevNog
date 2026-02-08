"""devnog qa command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from devnog.core.config import load_config
from devnog.core.output import console, get_progress, print_qa_verdict
from devnog.fix.engine import FixEngine


@click.command()
@click.argument("target", default=".")
@click.option("--dashboard", "open_dashboard", is_flag=True, help="Open results in dashboard")
@click.option("--fix", "auto_fix", is_flag=True, help="Fix all auto-fixable readiness gaps")
@click.option("--strict", is_flag=True, help="Fail CI if not fully ready")
@click.option("--quick", is_flag=True, help="Quick check (skip slow analysis)")
def qa(target: str, open_dashboard: bool, auto_fix: bool, strict: bool, quick: bool):
    """Validate production readiness.

    TARGET can be a directory path. Defaults to current directory.

    Checks things tests don't cover: error handling, timeouts,
    infrastructure, security config, and more.
    """
    target_path = Path(target).resolve()
    project_path = target_path if target_path.is_dir() else Path.cwd()
    config = load_config(project_path)

    try:
        from devnog.qa.engine import QAGate
    except ImportError:
        console.print("[red]QA module not available.[/red]")
        return

    with get_progress() as progress:
        task = progress.add_task("Running QA checks...", total=None)
        gate = QAGate(project_path)
        verdict = gate.evaluate()
        progress.update(task, completed=True)

    print_qa_verdict(verdict)

    if auto_fix:
        fix_engine = FixEngine(project_path, config)
        fixable = [f for f in verdict.warnings + verdict.failures if f.is_auto_fixable]
        if fixable:
            results = fix_engine.apply_all_safe(fixable)
            success = sum(1 for r in results if r.success)
            console.print(f"\n  [green]{success} QA fixes applied.[/green]")
        else:
            console.print("\n  No auto-fixable QA issues found.")

    if open_dashboard:
        from devnog.dashboard.server import DashboardServer
        server = DashboardServer(project_path)
        server.start()

    if strict and verdict.verdict == "FAIL":
        sys.exit(1)
