"""devnog undo command."""

from __future__ import annotations

from pathlib import Path

import click

from devnog.core.output import console, print_fix_result
from devnog.fix.undo import UndoManager


@click.command()
@click.argument("finding_id", required=False)
@click.option("--last", is_flag=True, help="Undo all fixes from the last fix session")
@click.option("--list", "list_all", is_flag=True, help="List all undoable fixes")
def undo(finding_id: str | None, last: bool, list_all: bool):
    """Undo previously applied fixes.

    Pass a FINDING_ID to undo a specific fix, or use --last to undo
    the entire last fix session.
    """
    project_path = Path.cwd()
    manager = UndoManager(project_path)

    if list_all:
        entries = manager.list_undoable()
        if not entries:
            console.print("\n  No undoable fixes found.\n")
            return

        console.print("\n  [bold]Undoable Fixes[/bold]\n")
        for entry in entries:
            console.print(f"  {entry.finding_id}  {entry.file}  [{entry.timestamp}]")
        console.print()
        return

    if last:
        results = manager.undo_last_session()
        if not results:
            console.print("\n  No recent fix session to undo.\n")
            return

        console.print("\n  [bold]Undoing last fix session:[/bold]\n")
        for result in results:
            print_fix_result(result)
        console.print()
        return

    if finding_id:
        result = manager.undo(finding_id)
        print_fix_result(result)
        return

    console.print("\n  Usage: devnog undo <FINDING_ID> or devnog undo --last")
    console.print("  Run `devnog undo --list` to see available undos.\n")
