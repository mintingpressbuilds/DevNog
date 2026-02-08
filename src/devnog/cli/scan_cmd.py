"""devnog scan command."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from devnog.core.config import ensure_gitignore, get_devnog_dir, load_config
from devnog.core.input_resolver import InputResolver
from devnog.core.output import console, get_progress, print_scan_report
from devnog.scanner.engine import Scanner

resolver = InputResolver()


@click.command()
@click.argument("target", default=".")
@click.option("--dashboard", "open_dashboard", is_flag=True, help="Open interactive dashboard with report")
@click.option("--export", "export_fmt", type=click.Choice(["html", "json"]), help="Export report format")
@click.option("--fail-under", type=int, default=0, help="Fail if score below threshold (for CI)")
@click.option("--fix", "auto_fix", is_flag=True, help="Auto-fix all safe issues after scan")
@click.option("--only", type=str, default=None, help="Scan only specific categories (comma-separated)")
def scan(target: str, open_dashboard: bool, export_fmt: str | None, fail_under: int, auto_fix: bool, only: str | None):
    """Scan codebase for issues and produce a health report.

    TARGET can be a directory path, .zip file, or GitHub URL.
    """
    config = load_config(Path.cwd())

    if only:
        config.scan.categories = [c.strip() for c in only.split(",")]

    # First run detection
    devnog_dir = get_devnog_dir(Path.cwd())
    first_run_marker = devnog_dir / ".initialized"
    is_first_run = not first_run_marker.exists()

    if is_first_run:
        console.print(f"\n  [bold]DevNog v0.1.0[/bold] — First run detected.")
        console.print(f"  Created .devnog/ directory.")
        ensure_gitignore(Path.cwd())
        console.print(f"  Added .devnog/ to .gitignore.\n")
        first_run_marker.touch()

    # Resolve input
    resolved = asyncio.run(resolver.resolve(target))

    try:
        with get_progress() as progress:
            task = progress.add_task(f"Scanning {resolved.source_type}: {resolved.original_target}...", total=None)

            scanner = Scanner(resolved.path, config)
            report = scanner.scan()
            report.source_type = resolved.source_type
            report.is_temp = resolved.is_temp

            progress.update(task, completed=True)

        # Print report
        print_scan_report(report)

        # Export if requested
        if export_fmt == "json":
            output = _report_to_dict(report)
            export_path = devnog_dir / "reports"
            export_path.mkdir(exist_ok=True)
            out_file = export_path / "scan-report.json"
            out_file.write_text(json.dumps(output, indent=2, default=str))
            console.print(f"\n  [dim]JSON report saved to {out_file}[/dim]")
        elif export_fmt == "html":
            export_path = devnog_dir / "reports"
            export_path.mkdir(exist_ok=True)
            out_file = export_path / "scan-report.html"
            out_file.write_text(_report_to_html(report))
            console.print(f"\n  [dim]HTML report saved to {out_file}[/dim]")

        # Auto-fix if requested
        if auto_fix and not resolved.is_temp:
            from devnog.fix.engine import FixEngine
            engine = FixEngine(resolved.path, config)
            results = engine.apply_all_safe(report.findings)
            if results:
                success = sum(1 for r in results if r.success)
                console.print(f"\n  [green]{success} auto-fixes applied.[/green]")
                console.print("  [dim]Run `devnog undo` to revert.[/dim]")
        elif auto_fix and resolved.is_temp:
            console.print(
                "\n  [yellow]Read-only scan. Clone the repo locally to apply fixes.[/yellow]"
            )

        # Open dashboard if requested
        if open_dashboard:
            from devnog.dashboard.server import DashboardServer
            server = DashboardServer(resolved.path)
            server.start()

        # CI fail-under check
        effective_fail_under = fail_under or config.scan.fail_under
        if effective_fail_under and report.overall_score < effective_fail_under:
            console.print(
                f"\n  [red]Score {report.overall_score} is below threshold {effective_fail_under}.[/red]"
            )
            sys.exit(1)

    finally:
        asyncio.run(resolver.cleanup(resolved))


def _report_to_dict(report) -> dict:
    """Convert ScanReport to a JSON-serializable dict."""
    return {
        "overall_score": report.overall_score,
        "total_lines": report.total_lines,
        "total_files": report.total_files,
        "total_dependencies": report.total_dependencies,
        "scanned_at": str(report.scanned_at),
        "project_name": report.project_name,
        "category_scores": {
            k: {"score": v.score, "findings_count": len(v.findings)}
            for k, v in report.category_scores.items()
        },
        "findings": [
            {
                "check_id": f.check_id,
                "category": f.category.value,
                "severity": f.severity.value,
                "message": f.message,
                "file": str(f.file) if f.file else None,
                "line": f.line,
                "fix_type": f.fix_type.value,
                "suggestion": f.suggestion,
            }
            for f in report.findings
        ],
    }


def _report_to_html(report) -> str:
    """Generate a simple HTML report."""
    findings_html = ""
    for f in report.findings:
        color = "#e74c3c" if f.severity.value == "critical" else "#f39c12" if f.severity.value == "warning" else "#3498db"
        findings_html += f"""
        <tr>
            <td><span style="color:{color}">●</span> {f.check_id}</td>
            <td>{f.message}</td>
            <td>{f.file}:{f.line}</td>
            <td>{f.fix_type.value}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><title>DevNog Scan Report</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
h1 {{ color: #00d4ff; }}
.score {{ font-size: 48px; font-weight: bold; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
th {{ background: #16213e; }}
</style></head>
<body>
<h1>DevNog Health Report</h1>
<p class="score">{report.overall_score}/100</p>
<p>{report.total_files} files | {report.total_lines:,} lines | {len(report.findings)} issues</p>
<table>
<tr><th>Check</th><th>Issue</th><th>Location</th><th>Fix Type</th></tr>
{findings_html}
</table>
</body></html>"""
