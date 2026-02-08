"""devnog guardian command."""

from __future__ import annotations

from pathlib import Path

import click

from devnog.core.config import get_devnog_dir, load_config
from devnog.core.output import console


@click.command()
@click.option("--status", is_flag=True, help="Show Guardian status")
@click.option("--audit", is_flag=True, help="Show healing audit log (Pro)")
@click.option("--report", is_flag=True, help="Show runtime failure report")
def guardian(status: bool, audit: bool, report: bool):
    """Guardian runtime protection status and reports.

    Use `from devnog import guard` in your app to enable Guardian.
    """
    project_path = Path.cwd()
    devnog_dir = get_devnog_dir(project_path)

    if audit:
        _show_audit(devnog_dir)
        return

    if report:
        _show_report(project_path)
        return

    # Default: show status
    _show_status(devnog_dir)


def _show_status(devnog_dir: Path):
    """Show Guardian status."""
    captures_db = devnog_dir / "captures.db"
    audit_log = devnog_dir / "healing_audit.log"

    console.print("\n  [bold]Guardian Status[/bold]\n")

    if captures_db.exists():
        size = captures_db.stat().st_size
        console.print(f"  Capture store: {size / 1024:.1f} KB")
    else:
        console.print("  Capture store: [dim]not initialized[/dim]")

    if audit_log.exists():
        lines = audit_log.read_text().strip().splitlines()
        console.print(f"  Healing audit log: {len(lines)} entries")
    else:
        console.print("  Healing audit log: [dim]not active[/dim]")

    from devnog.core.license import get_license_manager
    lm = get_license_manager()
    tier = lm.get_tier()
    console.print(f"  License tier: {tier.value}")

    if tier.value == "free":
        console.print("  Healing: [dim]observe-only (upgrade to Pro for auto-healing)[/dim]")
    else:
        console.print("  Healing: [green]active[/green]")
    console.print()


def _show_audit(devnog_dir: Path):
    """Show healing audit log."""
    from devnog.core.license import get_license_manager
    lm = get_license_manager()
    if not lm.require_pro("Healing audit log"):
        return

    audit_log = devnog_dir / "healing_audit.log"
    if not audit_log.exists():
        console.print("\n  No healing audit log found.\n")
        return

    console.print("\n  [bold]Healing Audit Log[/bold]\n")
    lines = audit_log.read_text().strip().splitlines()
    for line in lines[-20:]:  # Show last 20 entries
        console.print(f"  {line}")
    console.print()


def _show_report(project_path: Path):
    """Show runtime failure report."""
    try:
        from devnog.capture.store import CaptureStore
        store = CaptureStore(project_path)
        captures = store.get_recent(limit=20)

        if not captures:
            console.print("\n  No runtime failures captured.\n")
            return

        console.print("\n  [bold]Runtime Failure Report[/bold]\n")
        for cap in captures:
            console.print(
                f"  [red]{cap.error_type}[/red] in {cap.function_name}"
                f"  ({cap.occurrence_count} occurrences)"
            )
            console.print(f"    {cap.file_path}:{cap.line_number}")
            console.print(f"    {cap.error_message}")
            console.print()
    except Exception as e:
        console.print(f"\n  [red]Error loading captures: {e}[/red]\n")
