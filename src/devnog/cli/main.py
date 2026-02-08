"""Click CLI entry point for DevNog."""

from __future__ import annotations

import click

from devnog._version import __version__


@click.group()
@click.version_option(version=__version__, prog_name="devnog")
def cli():
    """DevNog - Developer's Bulletproofing Toolkit.

    Scan your code, see every problem, and fix them with one click.
    """
    pass


# Import and register subcommands
from devnog.cli.scan_cmd import scan  # noqa: E402
from devnog.cli.fix_cmd import fix  # noqa: E402
from devnog.cli.qa_cmd import qa  # noqa: E402
from devnog.cli.dashboard_cmd import dashboard  # noqa: E402
from devnog.cli.guardian_cmd import guardian  # noqa: E402
from devnog.cli.undo_cmd import undo  # noqa: E402
from devnog.cli.history_cmd import history  # noqa: E402
from devnog.cli.compliance_cmd import compliance  # noqa: E402

cli.add_command(scan)
cli.add_command(fix)
cli.add_command(qa)
cli.add_command(dashboard)
cli.add_command(guardian)
cli.add_command(undo)
cli.add_command(history)
cli.add_command(compliance)


if __name__ == "__main__":
    cli()
