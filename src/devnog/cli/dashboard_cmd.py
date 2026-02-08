"""devnog dashboard command."""

from __future__ import annotations

from pathlib import Path

import click

from devnog.core.config import load_config
from devnog.core.output import console


@click.command()
@click.option("--port", type=int, default=None, help="Port to serve on (default: 7654)")
@click.option("--no-open", is_flag=True, help="Don't auto-open browser")
def dashboard(port: int | None, no_open: bool):
    """Open the interactive localhost dashboard.

    Serves a visual web UI on http://localhost:7654 with
    clickable [FIX] buttons, live score updates, and diff previews.
    """
    project_path = Path.cwd()
    config = load_config(project_path)

    effective_port = port or config.dashboard.port
    auto_open = not no_open and config.dashboard.auto_open_browser

    console.print(f"\n  [bold]DevNog Dashboard[/bold]")
    console.print(f"  Starting on http://localhost:{effective_port}")

    try:
        from devnog.dashboard.server import DashboardServer
        server = DashboardServer(project_path, port=effective_port)
        server.start(open_browser=auto_open)
    except KeyboardInterrupt:
        console.print("\n  Dashboard stopped.")
