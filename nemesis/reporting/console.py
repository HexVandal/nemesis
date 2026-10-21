"""Rich console renderer: live progress plus the final summary table."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "cyan",
}


def print_banner(console: Console, target: str, profile: str, scope: str) -> None:
    """Print the opening banner."""
    console.print(
        Panel(
            Text.from_markup(
                f"[bold]nemesis[/bold] v0.1.0\n"
                f"[dim]target[/dim]  {target}\n"
                f"[dim]profile[/dim] {profile}\n"
                f"[dim]scope[/dim]   {scope}"
            ),
            title="nemesis",
            border_style="blue",
            expand=False,
        )
    )


def print_summary(console: Console, result: ScanResult) -> None:
    """Print the final results table."""
    counts = result.counts()

    table = Table(title=f"nemesis - {result.target.base_url}", header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Finding")
    table.add_column("Target", overflow="ellipsis", max_width=48)
    table.add_column("Confidence")

    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        group = [f for f in result.findings if f.severity == severity]
        if not group:
            continue
        for index, finding in enumerate(group):
            table.add_row(
                Text(severity.name, style=_SEVERITY_STYLE[severity]) if index == 0 else "",
                finding.title,
                finding.target,
                Text(finding.confidence.value, style=finding.confidence.color),
            )

    if result.findings:
        console.print()
        console.print(table)
    else:
        console.print("\n[green]No findings.[/green]")

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column(style="bold")
    summary.add_row("Critical", str(counts["CRITICAL"]))
    summary.add_row("High", str(counts["HIGH"]))
    summary.add_row("Medium", str(counts["MEDIUM"]))
    summary.add_row("Low", str(counts["LOW"]))
    summary.add_row("Info", str(counts["INFO"]))
    summary.add_row("Risk score", f"{result.risk_score()}/100")
    summary.add_row(
        "Confirmed", f"{len(result.confirmed())}/{len(result.findings)}"
    )
    if result.high_confidence():
        summary.add_row("High conf.", str(len(result.high_confidence())))
    summary.add_row("Endpoints", str(len(result.endpoints)))
    summary.add_row("Forms", str(len(result.forms)))
    summary.add_row("Requests", str(result.stats.get("requests_sent", 0)))
    summary.add_row("Duration", f"{result.duration_seconds}s")

    console.print()
    console.print(Panel(summary, title="Summary", border_style="blue", expand=False))


def print_finding(console: Console, finding) -> None:
    """Print a single finding in detail."""
    style = _SEVERITY_STYLE.get(finding.severity, "white")
    console.print(
        f"\n[{style}]{finding.severity.name}[/] [bold]{finding.title}[/]  "
        f"[dim]{finding.target}[/dim]"
    )
    console.print(f"  {finding.description}")
    if finding.remediation:
        console.print(f"  [green]fix:[/green] {finding.remediation}")


def print_proofs(console: Console, result: ScanResult, limit: int = 5) -> None:
    """Print the exploit transcript for the strongest findings.

    This is the part that separates nemesis from a template matcher: every
    confirmed finding carries the baseline request, the payload and the
    observed difference, so a reader can judge the result without rerunning
    the scan.
    """
    proofs = [
        finding
        for finding in result.findings
        if finding.confidence.value in ("confirmed", "high")
        and finding.evidence.response
    ]
    if not proofs:
        return

    proofs.sort(key=lambda f: (-f.severity.value, -f.confidence.rank))
    console.print()
    console.print(
        Panel(
            Text(
                "Each finding below is shown with the evidence that produced "
                "it. Active checks were proven by differential analysis: a "
                "benign request and a payload request were sent to the same "
                "endpoint and the responses were compared. Passive checks, "
                "such as a missing header, are reported from the response "
                "itself and are not differential experiments.",
                style="dim",
            ),
            title="Proof of exploitability",
            border_style="magenta",
            expand=False,
        )
    )

    for finding in proofs[:limit]:
        style = _SEVERITY_STYLE.get(finding.severity, "white")
        console.print()
        console.print(
            f"  [{style}]{finding.severity.name}[/] [bold]{finding.title}[/] "
            f"[dim]{finding.target}[/dim]"
        )
        body = Text()
        for line in finding.evidence.response.strip().splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("baseline"):
                body.append(stripped + "\n", style="dim")
            elif stripped.lower().startswith(("payload", "probe", "delta")):
                body.append(stripped + "\n", style="bold cyan")
            else:
                body.append(stripped + "\n")
        console.print(Panel(body, border_style="grey42", padding=(0, 1)))
