"""Rich terminal formatting for DevNog output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from devnog.core.models import (
    Finding,
    FixProposal,
    FixResult,
    ScanReport,
    Severity,
    QAVerdict,
)

console = Console()
error_console = Console(stderr=True)


SEVERITY_ICONS = {
    Severity.CRITICAL: "[red]\u25cf[/red]",
    Severity.WARNING: "[yellow]\u25cf[/yellow]",
    Severity.INFO: "[blue]\u25cf[/blue]",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.WARNING: "yellow",
    Severity.INFO: "blue",
}


def score_color(score: int) -> str:
    """Return color name based on score."""
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    return "red"


def score_icon(score: int) -> str:
    """Return icon based on score."""
    if score >= 80:
        return "[green]\u2705[/green]"
    elif score >= 60:
        return "[yellow]\u26a0\ufe0f[/yellow]"
    return "[red]\u274c[/red]"


def progress_bar(score: int, width: int = 10) -> str:
    """Create a text-based progress bar."""
    filled = round(score / 100 * width)
    empty = width - filled
    color = score_color(score)
    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"


def format_finding(finding: Finding) -> str:
    """Format a single finding for terminal output."""
    icon = SEVERITY_ICONS.get(finding.severity, "\u25cf")
    fix_label = ""
    if finding.is_auto_fixable:
        fix_label = " [dim](auto)[/dim]"
    elif finding.is_ai_fixable:
        fix_label = " [dim](AI)[/dim]"

    location = ""
    if finding.file:
        location = f"  {finding.file}"
        if finding.line:
            location += f":{finding.line}"

    return (
        f"  {icon} {finding.check_id}  {finding.message}{location}\n"
        f"     Fix: devnog fix {finding.check_id}{fix_label}"
    )


def print_scan_report(report: ScanReport) -> None:
    """Print the full scan report card to terminal."""
    color = score_color(report.overall_score)
    icon = score_icon(report.overall_score)

    lines = []
    lines.append("")
    lines.append(f"  Overall Score:  [{color}]{report.overall_score}/100[/{color}]  {icon}")
    lines.append("")

    # Category breakdown
    category_order = [
        ("code_quality", "Code Quality"),
        ("security", "Security"),
        ("error_handling", "Error Handling"),
        ("dependencies", "Dependencies"),
    ]
    for cat_key, cat_label in category_order:
        if cat_key in report.category_scores:
            cs = report.category_scores[cat_key]
            bar = progress_bar(cs.score)
            extra = ""
            crit = sum(
                1 for f in cs.findings if f.severity == Severity.CRITICAL
            )
            if crit > 0:
                extra = f"  [red]<- {crit} critical[/red]"
            lines.append(f"  {cat_label:<18} {bar}  {cs.score}/100{extra}")

    lines.append("")

    # Findings
    sorted_findings = sorted(
        report.findings,
        key=lambda f: (0 if f.severity == Severity.CRITICAL else 1 if f.severity == Severity.WARNING else 2),
    )
    for finding in sorted_findings:
        lines.append(format_finding(finding))
        lines.append("")

    # Summary
    lines.append(
        f"  {report.auto_fixable_count} auto-fixable | "
        f"{report.ai_fixable_count} AI-fixable | "
        f"{report.manual_count} manual"
    )
    lines.append("")
    lines.append("  Quick fix: [bold]devnog fix --all[/bold]")
    lines.append("  Dashboard: [bold]devnog dashboard[/bold]")
    lines.append("")
    lines.append(
        f"  {report.total_lines:,} lines | "
        f"{report.total_files} files | "
        f"{report.total_dependencies} dependencies"
    )

    title = "DevNog Health Report"
    if report.project_name:
        title += f"  {report.project_name}"
        if report.project_version:
            title += f" v{report.project_version}"

    console.print(Panel(
        "\n".join(lines),
        title=f"[bold]{title}[/bold]",
        border_style=color,
        padding=(0, 1),
    ))


def print_fix_preview(proposal: FixProposal) -> None:
    """Print a fix preview to terminal."""
    lines = []

    # Confidence
    conf_color = "green" if proposal.confidence == "high" else "yellow" if proposal.confidence == "medium" else "red"
    conf_filled = round(proposal.confidence_score * 12)
    conf_bar = "█" * conf_filled + "░" * (12 - conf_filled)
    lines.append(f"  Confidence: [{conf_color}]{conf_bar}[/{conf_color}] {proposal.confidence.upper()}")

    if proposal.confidence_reason:
        lines.append(f"  {proposal.confidence_reason}")
    lines.append("")

    # Description
    lines.append(f"  {proposal.description}")
    lines.append("")

    # Diff
    if proposal.file:
        lines.append(f"  {proposal.file}:{proposal.line_start}")
    for diff_line in proposal.diff.splitlines():
        if diff_line.startswith("-"):
            lines.append(f"  [red]{diff_line}[/red]")
        elif diff_line.startswith("+"):
            lines.append(f"  [green]{diff_line}[/green]")
        else:
            lines.append(f"  {diff_line}")

    # Side effects
    if proposal.side_effects:
        lines.append("")
        lines.append("  [yellow]Potential side effects:[/yellow]")
        for se in proposal.side_effects:
            lines.append(f"    - {se}")

    # Manual steps
    if proposal.manual_steps:
        lines.append("")
        lines.append("  [cyan]Manual steps required:[/cyan]")
        for step in proposal.manual_steps:
            lines.append(f"    - {step}")

    console.print(Panel(
        "\n".join(lines),
        title=f"[bold]Fix Preview — {proposal.finding_id}[/bold]",
        border_style=conf_color,
        padding=(0, 1),
    ))


def print_fix_result(result: FixResult) -> None:
    """Print a single fix result."""
    if result.success:
        console.print(f"  [green]\u2705 {result.finding_id}[/green]  {result.message}")
    else:
        console.print(f"  [red]\u274c {result.finding_id}[/red]  {result.message}")

    if result.manual_steps:
        for step in result.manual_steps:
            console.print(f"     [cyan]-> {step}[/cyan]")


def print_fix_summary(results: list[FixResult], old_score: int, new_score: int) -> None:
    """Print summary after applying multiple fixes."""
    success = sum(1 for r in results if r.success)
    failed = len(results) - success
    delta = new_score - old_score

    console.print()
    if success > 0:
        console.print(f"  [green]{success} fixes applied.[/green]")
    if failed > 0:
        console.print(f"  [red]{failed} fixes failed.[/red]")

    delta_str = f"+{delta}" if delta >= 0 else str(delta)
    color = score_color(new_score)
    console.print(f"  Score: {old_score} -> [{color}]{new_score}[/{color}] ({delta_str})")
    console.print("  [dim]Run `devnog undo` to revert any fix.[/dim]")
    console.print()


def print_qa_verdict(verdict: QAVerdict) -> None:
    """Print QA Gate verdict."""
    if verdict.verdict == "PASS":
        verdict_display = "[green bold]PASS[/green bold]"
        border = "green"
    elif verdict.verdict == "CONDITIONAL PASS":
        verdict_display = "[yellow bold]CONDITIONAL PASS[/yellow bold]"
        border = "yellow"
    else:
        verdict_display = "[red bold]FAIL[/red bold]"
        border = "red"

    lines = []
    lines.append("")
    lines.append(f"  Verdict:  {verdict_display}  ({verdict.score}/100)")
    lines.append("")

    for f in verdict.passed_checks:
        lines.append(f"  [green]\u2705 PASS[/green]  {f.message}")

    for f in verdict.warnings:
        lines.append(f"  [yellow]\u26a0\ufe0f  {f.check_id}[/yellow]  {f.message}  [dim]\\[FIX][/dim]")

    for f in verdict.failures:
        lines.append(f"  [red]\u274c {f.check_id}[/red]  {f.message}  [dim]\\[FIX][/dim]")

    lines.append("")
    lines.append("  Fix: [bold]devnog qa --fix[/bold]")

    console.print(Panel(
        "\n".join(lines),
        title="[bold]DevNog QA Gate — Production Readiness[/bold]",
        border_style=border,
        padding=(0, 1),
    ))


def get_progress() -> Progress:
    """Create a progress instance for scanning."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )
