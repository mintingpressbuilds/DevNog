"""devnog history command (Enterprise)."""

from __future__ import annotations

import json
from pathlib import Path

import click

from devnog.core.license import get_license_manager
from devnog.core.output import console


@click.command()
@click.option("--json", "as_json", is_flag=True, help="Export as JSON")
@click.option("--days", type=int, default=90, help="Number of days of history")
def history(as_json: bool, days: int):
    """Show scan score history over time (Enterprise).

    Tracks your codebase health score progression.
    """
    lm = get_license_manager()
    if not lm.require_enterprise("Historical trending"):
        return

    try:
        from devnog.enterprise.trending import HistoryTracker
        tracker = HistoryTracker(Path.cwd())
        entries = tracker.get_trend(days=days)

        if not entries:
            console.print("\n  No history data yet. Run `devnog scan` to start tracking.\n")
            return

        if as_json:
            output = [
                {
                    "date": str(e.scanned_at),
                    "overall_score": e.overall_score,
                    "git_commit": e.git_commit,
                }
                for e in entries
            ]
            click.echo(json.dumps(output, indent=2))
            return

        console.print("\n  [bold]DevNog Score History[/bold]\n")

        # Simple text chart
        max_score = max(e.overall_score for e in entries) if entries else 100
        for entry in entries[-20:]:  # Show last 20
            bar_len = round(entry.overall_score / 100 * 40)
            bar = "█" * bar_len
            date_str = entry.scanned_at.strftime("%Y-%m-%d")
            console.print(f"  {date_str}  [green]{bar}[/green] {entry.overall_score}")

        if len(entries) >= 2:
            first = entries[0].overall_score
            last = entries[-1].overall_score
            delta = last - first
            delta_str = f"+{delta}" if delta >= 0 else str(delta)
            console.print(f"\n  Trend: {first} -> {last} ({delta_str})")

        console.print()

    except Exception as e:
        console.print(f"\n  [red]Error loading history: {e}[/red]\n")
