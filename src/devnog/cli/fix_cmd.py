"""devnog fix command."""

from __future__ import annotations

from pathlib import Path

import click
from rich.prompt import Confirm

from devnog.core.config import get_devnog_dir, load_config
from devnog.core.output import (
    console,
    print_fix_preview,
    print_fix_result,
    print_fix_summary,
)
from devnog.fix.engine import FixEngine
from devnog.scanner.engine import Scanner


@click.command()
@click.argument("finding_id", required=False)
@click.option("--all", "fix_all", is_flag=True, help="Fix all auto-fixable issues")
@click.option("--category", type=str, help="Fix all issues in a category")
@click.option("--ai", is_flag=True, help="Use AI-powered fix (requires ANTHROPIC_API_KEY)")
@click.option("--preview", is_flag=True, help="Preview fix without applying")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option("--runtime", is_flag=True, help="Fix runtime failures captured by Guardian")
@click.option("--target", "-t", "target", default=".", help="Target directory to fix (default: current dir)")
def fix(
    finding_id: str | None,
    fix_all: bool,
    category: str | None,
    ai: bool,
    preview: bool,
    yes: bool,
    runtime: bool,
    target: str,
):
    """Fix issues found by the scanner.

    Pass a specific FINDING_ID (e.g., SEC-001) or use --all for batch fixes.
    Use --target to specify a directory other than the current one.
    """
    target_path = Path(target).resolve()
    project_path = target_path if target_path.is_dir() else Path.cwd()
    config = load_config(project_path)
    fix_engine = FixEngine(project_path, config)

    if runtime:
        _fix_runtime(fix_engine)
        return

    # Run a scan first to get current findings
    scanner = Scanner(project_path, config)
    report = scanner.scan()
    old_score = report.overall_score

    if fix_all:
        _fix_all(fix_engine, report, config, yes, project_path)
        return

    if category:
        findings = [f for f in report.findings if f.category.value == category]
        if not findings:
            console.print(f"\n  No issues found in category '{category}'.\n")
            return
        _fix_batch(fix_engine, findings, old_score, yes, preview)
        return

    if finding_id:
        # Find the specific finding
        finding = next((f for f in report.findings if f.check_id == finding_id), None)
        if not finding:
            console.print(f"\n  [red]Issue {finding_id} not found in current scan.[/red]")
            console.print("  Run `devnog scan` to see all issues.\n")
            return

        proposal = fix_engine.generate_fix(finding)
        if not proposal:
            if ai:
                console.print(f"\n  [yellow]AI fix generation requires async. Use `devnog fix {finding_id}` without --ai for rule-based fixes.[/yellow]\n")
            else:
                console.print(f"\n  [yellow]No auto-fix available for {finding_id}.[/yellow]")
                if finding.suggestion:
                    console.print(f"  Suggestion: {finding.suggestion}")
                console.print(f"  Try: devnog fix {finding_id} --ai\n")
            return

        print_fix_preview(proposal)

        if preview:
            return

        if not yes:
            if not Confirm.ask("  Apply this fix?", default=False):
                console.print("  [dim]Skipped.[/dim]")
                return

        result = fix_engine.apply_fix(proposal)
        print_fix_result(result)

        if result.success:
            new_report = scanner.scan()
            delta = new_report.overall_score - old_score
            delta_str = f"+{delta}" if delta >= 0 else str(delta)
            console.print(f"\n  Score: {old_score} -> {new_report.overall_score} ({delta_str})")
        return

    # No specific finding or --all
    console.print("\n  Usage: devnog fix <FINDING_ID> or devnog fix --all")
    console.print("  Run `devnog scan` to see available issues.\n")


def _fix_all(fix_engine: FixEngine, report, config, yes: bool, project_path: Path | None = None):
    """Handle --all flag."""
    devnog_dir = get_devnog_dir(project_path or Path.cwd())
    first_fix_marker = devnog_dir / ".first_fix_done"
    is_first_fix = not first_fix_marker.exists()

    auto_fixable = [f for f in report.findings if f.is_auto_fixable]
    ai_fixable = [f for f in report.findings if f.is_ai_fixable]
    manual = [f for f in report.findings if not f.is_auto_fixable and not f.is_ai_fixable]

    if not auto_fixable and not ai_fixable:
        console.print("\n  No fixable issues found.\n")
        return

    console.print("\n  [bold]DevNog Fix Engine[/bold]")
    console.print(f"  Analyzing {len(report.findings)} issues...\n")

    if auto_fixable:
        console.print("  [green]Auto-fixable (rule-based, safe to apply):[/green]")
        for f in auto_fixable:
            console.print(f"    {f.check_id}  {f.message}")
        console.print()

    if ai_fixable:
        console.print("  [yellow]AI-fixable (requires review):[/yellow]")
        for f in ai_fixable:
            console.print(f"    {f.check_id}  {f.message}")
        console.print()

    if manual:
        console.print("  [dim]Cannot auto-fix (manual guidance provided):[/dim]")
        for f in manual:
            console.print(f"    {f.check_id}  {f.message}")
        console.print()

    if is_first_fix:
        console.print("  [yellow]First time running fixes. Showing preview only.[/yellow]")
        affected_files = len({str(f.file) for f in auto_fixable if f.file})
        console.print(f"  {len(auto_fixable)} issues across {affected_files} file(s) will be fixed. All changes are reversible via `devnog undo`.")
        console.print("  Backups saved to .devnog/backups/")
        console.print("  [dim]Tip: Test on a git branch first.[/dim]\n")

    if not auto_fixable:
        console.print("  No auto-fixable issues. Run with --ai for AI-powered fixes.\n")
        return

    if not yes:
        if not Confirm.ask(f"  Apply all {len(auto_fixable)} safe fixes?", default=True):
            console.print("  [dim]Cancelled.[/dim]")
            return

    results = fix_engine.apply_all_safe(report.findings)

    console.print()
    for result in results:
        print_fix_result(result)

    # Rescan for new score
    scanner = Scanner(project_path or Path.cwd(), config)
    new_report = scanner.scan()
    print_fix_summary(results, report.overall_score, new_report.overall_score)

    remaining = len(new_report.findings)
    remaining_ai = sum(1 for f in new_report.findings if f.is_ai_fixable)
    remaining_manual = remaining - remaining_ai
    console.print(f"  Remaining issues: {remaining} ({remaining_ai} AI-fixable, {remaining_manual} need manual review)")

    if remaining_ai > 0:
        console.print("  Run `devnog fix --ai` to apply AI-generated fixes (requires ANTHROPIC_API_KEY).\n")

    first_fix_marker.touch()


def _fix_batch(fix_engine, findings, old_score, yes, preview):
    """Fix a batch of findings."""
    for finding in findings:
        proposal = fix_engine.generate_fix(finding)
        if not proposal:
            continue

        print_fix_preview(proposal)

        if preview:
            continue

        if not yes:
            if not Confirm.ask("  Apply this fix?", default=False):
                console.print("  [dim]Skipped.[/dim]\n")
                continue

        result = fix_engine.apply_fix(proposal)
        print_fix_result(result)
        console.print()


def _fix_runtime(fix_engine):
    """Handle --runtime flag: show and fix Guardian captures."""
    try:
        from devnog.capture.store import CaptureStore
        store = CaptureStore(Path.cwd())
        captures = store.get_recent(limit=20)

        if not captures:
            console.print("\n  No runtime failures captured.")
            console.print("  Add @capture or @healable decorators to capture failures.\n")
            return

        console.print("\n  [bold]Runtime Failure Report[/bold]\n")
        for i, cap in enumerate(captures):
            console.print(
                f"  [red]RT-{i+1:03d}[/red]  {cap.function_name}  "
                f"{cap.error_type}  ({cap.occurrence_count} occurrences)"
            )
        console.print()
    except Exception as e:
        console.print(f"\n  [red]Error loading captures: {e}[/red]\n")
