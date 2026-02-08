"""devnog compliance command (Enterprise)."""

from __future__ import annotations

from pathlib import Path

import click

from devnog.core.license import get_license_manager
from devnog.core.output import console


@click.command()
@click.option("--framework", type=click.Choice(["owasp", "soc2", "custom"]), default="owasp", help="Compliance framework")
@click.option("--export", "export_fmt", type=click.Choice(["pdf", "json", "html"]), default="pdf", help="Export format")
def compliance(framework: str, export_fmt: str):
    """Generate compliance reports (Enterprise).

    Maps scanner findings to compliance frameworks like OWASP Top 10 and SOC2.
    """
    lm = get_license_manager()
    if not lm.require_enterprise("Compliance reports"):
        return

    project_path = Path.cwd()

    try:
        from devnog.enterprise.compliance import ComplianceReporter
        from devnog.scanner.engine import Scanner
        from devnog.core.config import load_config

        config = load_config(project_path)
        scanner = Scanner(project_path, config)
        report = scanner.scan()

        reporter = ComplianceReporter(project_path)

        if export_fmt == "pdf":
            try:
                output_path = reporter.generate_pdf(framework, report)
                console.print(f"\n  [green]Compliance report generated: {output_path}[/green]\n")
            except ImportError:
                console.print(
                    "\n  [yellow]PDF generation requires reportlab.[/yellow]"
                    "\n  Install with: pip install devnog[enterprise]\n"
                )
        elif export_fmt == "json":
            output_path = reporter.generate_json(framework, report)
            console.print(f"\n  [green]Compliance report generated: {output_path}[/green]\n")
        elif export_fmt == "html":
            output_path = reporter.generate_html(framework, report)
            console.print(f"\n  [green]Compliance report generated: {output_path}[/green]\n")

    except Exception as e:
        console.print(f"\n  [red]Error generating report: {e}[/red]\n")
