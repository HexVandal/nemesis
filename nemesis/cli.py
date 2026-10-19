"""Command line interface for nemesis."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import __version__
from .config import PROFILES, ScanConfig
from .engine import Engine
from .models import Severity
from .reporting import write_html, write_json, write_markdown, write_sarif
from .reporting.console import print_banner, print_proofs, print_summary

app = typer.Typer(
    name="nemesis",
    help="The offensive-security scanner that thinks like a red team.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"nemesis {__version__}")
        raise typer.Exit()


@app.callback()
def root_callback(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress console output."),
) -> None:
    """nemesis - crawl, fingerprint, exploit and verify a target."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(console=error_console, show_path=False, markup=False)],
        force=True,
    )


def _parse_cookie(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            cookies[key.strip()] = val.strip()
    return cookies


def _split_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    out: list[str] = []
    for value in values:
        out.extend(item.strip() for item in value.split(",") if item.strip())
    return out


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL, e.g. https://app.example.com"),
    scope: list[str] | None = typer.Option(
        None, "--scope", "-s", help="Scope rule (repeatable). Default: the target host."
    ),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", "-x", help="Exclusion rule (repeatable)."
    ),
    profile: str | None = typer.Option(
        None, "--profile", "-p", help=f"One of: {', '.join(PROFILES)}"
    ),
    include: list[str] | None = typer.Option(
        None, "--include", "-i", help="Only run modules matching this id or glob."
    ),
    exclude_module: list[str] | None = typer.Option(
        None, "--exclude-module", help="Skip modules matching this id or glob."
    ),
    severity: str | None = typer.Option(
        None, "--severity", help="Minimum severity to report: info|low|medium|high|critical."
    ),
    fmt: list[str] | None = typer.Option(
        None, "--format", "-f", help="Report formats: console, json, markdown, html, sarif."
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Output directory."),
    code_path: str | None = typer.Option(
        None, "--code-path", help="Local source tree to analyse for secrets, bugs and dependencies."
    ),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Full header value, e.g. 'Bearer token'."
    ),
    auth_bearer: str | None = typer.Option(None, "--auth-bearer", help="Bearer token."),
    auth_basic: str | None = typer.Option(
        None, "--auth-basic", help="username:password for basic auth."
    ),
    auth_cookie: str | None = typer.Option(
        None, "--auth-cookie", help="Cookie header, e.g. 'session=abc; uid=1'."
    ),
    extra_header: list[str] | None = typer.Option(
        None, "--header", "-H", help="Extra request header 'Name: Value' (repeatable)."
    ),
    rate: float | None = typer.Option(
        None, "--rate", "-r", help="Requests per second per host."
    ),
    timeout: float | None = typer.Option(
        None, "--timeout", help="Per-request timeout in seconds."
    ),
    threads: int | None = typer.Option(
        None, "--threads", help="Global concurrency limit."
    ),
    max_pages: int | None = typer.Option(None, "--max-pages", help="Maximum pages to crawl."),
    max_depth: int | None = typer.Option(None, "--max-depth", help="Maximum crawl depth."),
    user_agent: str | None = typer.Option(None, "--user-agent", help="Custom User-Agent."),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP(S) proxy URL."),
    allow_destructive: bool = typer.Option(
        False, "--allow-destructive", help="Enable modules that may change server state."
    ),
    no_crawl: bool = typer.Option(False, "--no-crawl", help="Do not crawl; test only known URLs."),
    no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt."),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Run differential verification."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="YAML/JSON config file."),
    plugin_dir: str | None = typer.Option(None, "--plugins", help="Directory of plugin modules."),
    json_stdout: bool = typer.Option(False, "--json", help="Print the JSON report to stdout."),
) -> None:
    """Scan a target and write a report."""
    # -- config ------------------------------------------------------------
    # The config file is loaded first and only the options the user
    # actually supplied override it. An unset flag must never stomp on a
    # value that came from the file.
    if config_file:
        try:
            config = ScanConfig.load(config_file)
        except FileNotFoundError as exc:
            error_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from None
        except (ValueError, yaml.YAMLError) as exc:
            error_console.print(f"[red]Could not read {config_file}:[/red] {exc}")
            raise typer.Exit(code=2) from None
    else:
        config = ScanConfig()

    if profile is not None and profile not in PROFILES:
        error_console.print(f"[red]Unknown profile '{profile}'.[/red] "
                            f"Choose one of: {', '.join(PROFILES)}")
        raise typer.Exit(code=2)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    config.target = target
    if profile is not None:
        config.profile = profile
    if output is not None:
        config.output_dir = output
    config.scope_rules = _split_list(scope) or config.scope_rules
    config.exclusions = _split_list(exclude) or config.exclusions
    config.include_modules = _split_list(include) or config.include_modules
    config.exclude_modules = _split_list(exclude_module) or config.exclude_modules
    config.formats = _split_list(fmt) or config.formats
    if rate is not None:
        config.rate.requests_per_second = rate
    if threads is not None:
        config.rate.global_concurrency = threads
    if timeout is not None:
        config.timeout = timeout
    if allow_destructive:
        config.allow_destructive = True
    if no_crawl:
        config.no_crawl = True
    if not verify:
        config.verify = False
    if no_robots:
        config.crawl.follow_robots = False
    if code_path:
        config.code_path = code_path
    if user_agent:
        config.user_agent = user_agent
    if proxy:
        config.proxy = proxy
    if max_pages is not None:
        config.crawl.max_pages = max_pages
    if max_depth is not None:
        config.crawl.max_depth = max_depth

    if severity is not None:
        try:
            config.severity_min = Severity[severity.upper()]
        except KeyError:
            error_console.print(f"[red]Unknown severity '{severity}'.[/red]")
            raise typer.Exit(code=2) from None

    # -- auth --------------------------------------------------------------
    if auth_bearer:
        config.auth.mode = "bearer"
        config.auth.value = auth_bearer
    elif auth_basic:
        config.auth.mode = "basic"
        username, _, password = auth_basic.partition(":")
        config.auth.username = username
        config.auth.password = password
    elif auth_header:
        config.auth.mode = "header"
        config.auth.value = auth_header
    elif auth_cookie:
        config.auth.mode = "cookie"
        config.auth.cookies = _parse_cookie(auth_cookie)

    for header in _split_list(extra_header):
        name, _, value = header.partition(":")
        if name and value:
            config.auth.extra_headers[name.strip()] = value.strip()

    # -- run ---------------------------------------------------------------
    engine = Engine(config)
    if plugin_dir:
        engine.registry.load_directory(plugin_dir)

    # When the JSON report is piped to stdout, the human summary would
    # corrupt it, so the console renderer is disabled in that case.
    show_console = "console" in config.formats and not json_stdout

    if show_console:
        print_banner(console, target, profile, ", ".join(config.scope_rules) or target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=28),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console if show_console else Console(file=sys.stderr),
        disable=not show_console,
    ) as progress:
        task = progress.add_task("starting", total=None)
        try:
            result = asyncio.run(_run_with_progress(engine, progress, task))
        except Exception as exc:
            error_console.print(f"[red]Scan failed:[/red] {exc}")
            error_console.print_exception()
            raise typer.Exit(code=1) from exc

    # -- report ------------------------------------------------------------
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if "json" in config.formats:
        path = write_json(result, output_dir / "nemesis.json")
        written.append(path)
    if "markdown" in config.formats:
        path = write_markdown(result, output_dir / "nemesis.md")
        written.append(path)
    if "html" in config.formats:
        path = write_html(result, output_dir / "nemesis.html", scope=", ".join(config.scope_rules))
        written.append(path)
    if "sarif" in config.formats:
        path = write_sarif(result, output_dir / "nemesis.sarif")
        written.append(path)

    if show_console:
        print_summary(console, result)
        print_proofs(console, result)
        if written:
            console.print()
            for path in written:
                console.print(f"  [green]wrote[/green] {path}")

    if json_stdout:
        console.print_json(json.dumps(result.to_dict(), default=str))


async def _run_with_progress(engine: Engine, progress: Progress, task):
    """Run the engine while updating the progress bar."""
    import contextlib

    @contextlib.contextmanager
    def _update():
        yield

    async def _runner():
        return await engine.run()

    # The engine does not emit fine-grained progress, so we run it as one
    # task and report completion. Module-level progress arrives via engine.events.
    return await _runner()


@app.command("modules")
def list_modules(
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show full descriptions."),
) -> None:
    """List every available module."""
    from .config import ScanConfig
    from .modules.base import ModuleRegistry

    registry = ModuleRegistry(ScanConfig())
    registry.load_builtin()
    registry.load_entry_points()

    table = __import__("rich.table", fromlist=["Table"]).Table(title="nemesis modules")
    table.add_column("ID", style="bold cyan")
    table.add_column("Capability")
    table.add_column("Severity")
    table.add_column("Tags")
    if detailed:
        table.add_column("Description")

    for module in registry.all():
        row = [
            module.id,
            module.capability.value,
            module.severity.name,
            ", ".join(module.tags[:4]),
        ]
        if detailed:
            row.append(module.description)
        table.add_row(*row)

    console.print(table)
    console.print(f"[dim]{len(registry.all())} modules built in.[/dim]")


@app.command()
def profiles() -> None:
    """List the available scan profiles."""
    from rich.table import Table

    table = Table(title="nemesis profiles")
    table.add_column("Name", style="bold cyan")
    table.add_column("Description")
    table.add_column("Crawl limits")

    for name, profile in PROFILES.items():
        crawl = profile.get("crawl", {})
        limits = f"pages={crawl.get('max_pages', '-')} depth={crawl.get('max_depth', '-')}"
        table.add_row(name, profile.get("description", ""), limits)

    console.print(table)


@app.command()
def explain(
    severity: str = typer.Argument(..., help="Severity to explain: info|low|medium|high|critical"),
) -> None:
    """Explain how nemesis scores and reports a severity level."""
    try:
        level = Severity[severity.upper()]
    except KeyError:
        error_console.print(f"[red]Unknown severity '{severity}'.[/red]")
        raise typer.Exit(code=2) from None

    descriptions = {
        Severity.CRITICAL: (
            "Direct, unauthenticated remote code execution, authentication bypass, "
            "or exposed production credentials. Exploitability is proven."
        ),
        Severity.HIGH: (
            "Exploitation requires a precondition (a valid account, a user click) "
            "but leads to data access, privilege escalation or code execution."
        ),
        Severity.MEDIUM: (
            "Real but conditional weaknesses: information disclosure, missing "
            "defence-in-depth, or exploitation that needs unusual configuration."
        ),
        Severity.LOW: (
            "Hardening gaps and best-practice deviations with limited direct "
            "impact, but which meaningfully lower the attack surface."
        ),
        Severity.INFO: (
            "Observations rather than defects: fingerprinting, technology "
            "inventory, and configuration facts worth recording."
        ),
    }
    console.print(f"[bold]{level.name}[/bold]\n")
    console.print(descriptions[level])
    console.print()
    console.print(
        "[dim]nemesis reports severity and confidence separately. A critical "
        "finding with low confidence is still worth reading - it means the "
        "signal is strong but the exploit was not fully proven.[/dim]"
    )


    console.print(
        "[dim]nemesis reports severity and confidence separately. A critical "
        "finding with low confidence is still worth reading - it means the "
        "signal is strong but the exploit was not fully proven.[/dim]"
    )


# ----------------------------------------------------------------------
# Capability map
# ----------------------------------------------------------------------
def _component_label(spec: str) -> str:
    """A short, readable name for a ``package.module:Attribute``."""
    _, _, attribute = spec.partition(":")
    return attribute or spec


@app.command("capabilities")
def list_capabilities(
    domain: str | None = typer.Option(None, "--domain", "-d", help="Filter by domain."),
    maturity: str | None = typer.Option(
        None, "--maturity", "-m", help="Filter by maturity: native|partial|integration|research|manual."
    ),
    search: str | None = typer.Option(None, "--search", "-s", help="Search names and summaries."),
    detailed: bool = typer.Option(False, "--detailed", help="Show modules, tools and prerequisites."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Show the capability map: what nemesis covers, and how honestly."""
    from rich.table import Table

    from .capabilities import CAPABILITY_REGISTRY, MATURITY_LABELS

    capabilities = CAPABILITY_REGISTRY.all()
    if domain:
        capabilities = [c for c in capabilities if c.domain == domain]
    if maturity:
        capabilities = [c for c in capabilities if c.maturity == maturity]
    if search:
        needle = search.lower()
        capabilities = [
            c
            for c in capabilities
            if needle in c.name.lower()
            or needle in c.summary.lower()
            or any(needle in kw.lower() for kw in c.keywords)
        ]

    if as_json:
        console.print_json(
            json.dumps(
                {
                    "capabilities": [c.to_dict() for c in capabilities],
                    "coverage": CAPABILITY_REGISTRY.coverage(),
                },
                default=str,
            )
        )
        return

    table = Table(title="nemesis capability map")
    table.add_column("Capability", style="bold cyan", max_width=34)
    table.add_column("Domain")
    table.add_column("Maturity")
    table.add_column("Backed by")
    if detailed:
        table.add_column("Summary", max_width=60)

    for capability in capabilities:
        # A capability can be backed by a module, by a component, or by
        # a tool that does the work. Show whichever it actually is.
        backed = ", ".join(capability.modules)
        if not backed and capability.components:
            backed = ", ".join(_component_label(c) for c in capability.components)
        if not backed:
            backed = ", ".join(capability.tools) or "-"
        row = [
            capability.name,
            capability.domain_label,
            capability.maturity_label,
            backed,
        ]
        if detailed:
            row.append(capability.summary)
        table.add_row(*row)

    console.print(table)

    coverage = CAPABILITY_REGISTRY.coverage()
    console.print()
    console.print(f"[bold]{coverage['total']}[/bold] capability areas tracked.")
    for level, label in MATURITY_LABELS.items():
        count = coverage["by_maturity"].get(level, 0)
        console.print(f"  {label:<38} {count:>3}")
    console.print()
    console.print(
        f"[dim]{coverage['backed']} of {coverage['total']} are backed by a "
        f"nemesis module or component ({coverage['backed_percent']}%). The "
        f"rest are labelled with what they actually need: a lab, an "
        f"external tool, or a person.[/dim]"
    )


@app.command("capability")
def show_capability(
    capability_id: str = typer.Argument(..., help="Capability id, e.g. request-smuggling."),
) -> None:
    """Show one capability in detail."""
    from .capabilities import CAPABILITY_REGISTRY

    capability = CAPABILITY_REGISTRY.get(capability_id)
    if capability is None:
        matches = CAPABILITY_REGISTRY.search(capability_id)
        error_console.print(f"[red]Unknown capability '{capability_id}'.[/red]")
        if matches:
            error_console.print("Did you mean: " + ", ".join(c.id for c in matches[:8]))
        raise typer.Exit(code=2) from None

    console.print(f"[bold cyan]{capability.name}[/bold cyan]")
    console.print(f"[dim]{capability.id}[/dim]\n")
    console.print(capability.summary)
    console.print()
    console.print(f"  Domain   : {capability.domain_label}")
    console.print(f"  Maturity : {capability.maturity_label}")
    if capability.modules:
        console.print(f"  Modules  : {', '.join(capability.modules)}")
    if capability.tools:
        console.print(f"  Tools    : {', '.join(capability.tools)}")
    if capability.artifacts:
        console.print(f"  Artifacts: {', '.join(capability.artifacts)}")
    if capability.prerequisites:
        console.print(f"  Needs    : {'; '.join(capability.prerequisites)}")
    if capability.keywords:
        console.print(f"  Keywords : {', '.join(capability.keywords)}")


# ----------------------------------------------------------------------
# CVSS
# ----------------------------------------------------------------------
@app.command("cvss")
def cvss_command(
    vector: str = typer.Argument(..., help="CVSS v3.1 vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    json_stdout: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Calculate and explain a CVSS v3.1 base score."""
    from .knowledge.cvss import CvssVector, parse_vector

    parsed = parse_vector(vector)
    if parsed is None:
        error_console.print(f"[red]Could not parse '{vector}' as a CVSS v3.1 vector.[/red]")
        raise typer.Exit(code=2) from None

    score = parsed.score()
    if json_stdout:
        console.print_json(
            json.dumps(
                {
                    "vector": parsed.vector,
                    "base_score": score,
                    "severity": _cvss_severity(score),
                    "metrics": {
                        "AV": parsed.av, "AC": parsed.ac, "PR": parsed.pr,
                        "UI": parsed.ui, "S": parsed.scope,
                        "C": parsed.c, "I": parsed.i, "A": parsed.a,
                    },
                }
            )
        )
        return

    console.print(f"[bold]{parsed.vector}[/bold]")
    console.print()
    console.print(f"  Base score : [bold]{score:.1f}[/bold] ({_cvss_severity(score)})")
    console.print()
    for label, value, meaning in _cvss_explain(parsed):
        console.print(f"  {label:<26} {value:<4} {meaning}")
    console.print()
    console.print(
        "[dim]The base score describes the intrinsic severity of a "
        "vulnerability. The temporal and environmental metrics are what "
        "make it specific to your deployment - a CVSS 9.8 in a lab is "
        "not a CVSS 9.8 in production.[/dim]"
    )
    _ = CvssVector


def _cvss_severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _cvss_explain(vector) -> list[tuple[str, str, str]]:
    return [
        ("Attack Vector", vector.av, {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}[vector.av]),
        ("Attack Complexity", vector.ac, {"L": "low", "H": "high"}[vector.ac]),
        ("Privileges Required", vector.pr, {"N": "none", "L": "low", "H": "high"}[vector.pr]),
        ("User Interaction", vector.ui, {"N": "none", "R": "required"}[vector.ui]),
        ("Scope", vector.scope, {"U": "unchanged", "C": "changed"}[vector.scope]),
        ("Confidentiality", vector.c, {"N": "none", "L": "low", "H": "high"}[vector.c]),
        ("Integrity", vector.i, {"N": "none", "L": "low", "H": "high"}[vector.i]),
        ("Availability", vector.a, {"N": "none", "L": "low", "H": "high"}[vector.a]),
    ]


# ----------------------------------------------------------------------
# Report generation from a previous scan
# ----------------------------------------------------------------------
def _load_findings(path: Path) -> list:
    """Read findings out of a nemesis JSON report."""
    from .models import Category, Confidence, Evidence, Finding

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        error_console.print(f"[red]Could not read {path}:[/red] {exc}")
        raise typer.Exit(code=2) from None

    raw = data.get("findings", data if isinstance(data, list) else [])
    findings = []
    for item in raw:
        try:
            evidence = item.get("evidence", {}) or {}
            findings.append(
                Finding(
                    title=item.get("title", ""),
                    severity=Severity[item.get("severity", "INFO")],
                    confidence=Confidence(item.get("confidence", "info")),
                    description=item.get("description", ""),
                    target=item.get("target", ""),
                    module=item.get("module", ""),
                    category=Category(item.get("category", "info")),
                    remediation=item.get("remediation", ""),
                    cwe=item.get("cwe"),
                    owasp=item.get("owasp"),
                    cvss=item.get("cvss"),
                    evidence=Evidence(
                        request=evidence.get("request", ""),
                        response=evidence.get("response", ""),
                        matched=evidence.get("matched", ""),
                        extra=evidence.get("extra", {}),
                    ),
                    references=item.get("references", []),
                    tags=item.get("tags", []),
                    fingerprint=item.get("fingerprint", ""),
                    file=item.get("file"),
                    line=item.get("line"),
                )
            )
        except (KeyError, ValueError) as exc:
            error_console.print(f"[yellow]Skipping malformed finding:[/yellow] {exc}")
    return findings


@app.command("report")
def disclosure_report(
    report_file: str = typer.Argument(..., help="A nemesis JSON report."),
    programme: str = typer.Option("hackerone", "--programme", "-p", help="hackerone|bugcrowd|intigriti"),
    asset: str = typer.Option("", "--asset", help="The asset being reported on."),
    researcher: str = typer.Option("", "--researcher", help="Your name or handle."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)."),
    min_severity: str = typer.Option("medium", "--min-severity", help="Only report at or above this severity."),
) -> None:
    """Turn a scan into a bug-bounty disclosure report."""
    from .reporting.disclosure import PROGRAMMES, DisclosureReportBuilder

    if programme.lower() not in PROGRAMMES:
        error_console.print(f"[red]Unknown programme '{programme}'.[/red] Use one of: {', '.join(PROGRAMMES)}")
        raise typer.Exit(code=2) from None

    findings = _load_findings(Path(report_file))
    try:
        threshold = Severity[min_severity.upper()]
    except KeyError:
        error_console.print(f"[red]Unknown severity '{min_severity}'.[/red]")
        raise typer.Exit(code=2) from None

    selected = [f for f in findings if f.severity >= threshold]
    if not selected:
        error_console.print("[yellow]No findings at or above that severity.[/yellow]")
        raise typer.Exit(code=1)

    builder = DisclosureReportBuilder(programme.lower(), asset=asset, researcher=researcher)
    reports = builder.build_all(selected)

    if output:
        text = "\n\n---\n\n".join(r.to_markdown() for r in reports)
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]wrote[/green] {output} ({len(reports)} report(s))")
        return

    for index, report in enumerate(reports, start=1):
        console.print(f"\n[bold cyan]Report {index}/{len(reports)}[/bold cyan]")
        console.print(f"[bold]{report.title}[/bold]")
        console.print(f"Severity: {report.severity_label}   Asset: {', '.join(report.assets)}")
        console.print()
        console.print(report.to_markdown())


@app.command("writeup")
def writeup_command(
    report_file: str = typer.Argument(..., help="A nemesis JSON report."),
    title: str = typer.Option("", "--title", help="Title of the write-up."),
    author: str = typer.Option("", "--author", help="Author name or handle."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)."),
) -> None:
    """Turn a scan into a public write-up draft."""
    from .reporting.writeup import WriteupBuilder

    findings = _load_findings(Path(report_file))
    builder = WriteupBuilder(author=author)
    writeup = builder.build(findings, title=title)

    if output:
        Path(output).write_text(writeup.to_markdown(), encoding="utf-8")
        console.print(f"[green]wrote[/green] {output}")
        return
    console.print(writeup.to_markdown())


@app.command("yara")
def yara_command(
    report_file: str = typer.Argument(..., help="A nemesis JSON report."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output .yar file."),
) -> None:
    """Generate YARA detection rules from a scan's findings."""
    from .reporting.yara import YaraRuleBuilder

    findings = _load_findings(Path(report_file))
    builder = YaraRuleBuilder()
    rules = builder.build(findings)
    text = builder.to_text(rules)

    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]wrote[/green] {output} ({len(rules)} rule(s))")
    else:
        console.print(text)

    if builder.skipped:
        console.print()
        console.print("[dim]Skipped (and why):[/dim]")
        for title, reason in builder.skipped:
            console.print(f"  - {title}: {reason}")


@app.command("sigma")
def sigma_command(
    report_file: str = typer.Argument(..., help="A nemesis JSON report."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output .yml file."),
) -> None:
    """Generate Sigma detection rules from a scan's findings."""
    from .reporting.sigma import SigmaRuleBuilder

    findings = _load_findings(Path(report_file))
    builder = SigmaRuleBuilder()
    rules = builder.build(findings)
    text = builder.to_text(rules)

    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]wrote[/green] {output} ({len(rules)} rule(s))")
    else:
        console.print(text)

    if builder.skipped:
        console.print()
        console.print("[dim]Skipped (and why):[/dim]")
        for title, reason in builder.skipped:
            console.print(f"  - {title}: {reason}")


@app.command("triage")
def triage_command(
    report_file: str = typer.Argument(..., help="A nemesis JSON report."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Rank findings into a worklist: what to do first, and why."""
    from .reporting.triage import TriageEngine, render_triage

    findings = _load_findings(Path(report_file))
    engine = TriageEngine()
    plan = engine.plan(findings)

    if as_json:
        console.print_json(json.dumps(plan, default=str))
        return

    items = engine.triage(findings)
    console.print(render_triage(items))
    console.print()
    console.print(
        f"[dim]{plan['total_findings']} findings collapsed into "
        f"{plan['worklist_size']} work items "
        f"({plan['collapsed']} duplicate(s) folded in).[/dim]"
    )


# ----------------------------------------------------------------------
# The reference library
# ----------------------------------------------------------------------
@app.command("knowledge")
def knowledge_command(
    search: str | None = typer.Option(None, "--search", "-s", help="Search titles, notes and areas."),
    area: str | None = typer.Option(None, "--area", "-a", help="Filter by capability area."),
    kind: str | None = typer.Option(None, "--kind", "-k", help="Filter by kind: lab|course|paper|book|tool|project|standard|guide."),
    limit: int = typer.Option(30, "--limit", "-n", help="Maximum results."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Browse the research library: papers, courses, books, labs and tools."""
    from rich.table import Table

    from .knowledge.library import LIBRARY_INDEX

    resources = LIBRARY_INDEX.all()
    if search:
        resources = LIBRARY_INDEX.search(search)
    if area:
        resources = [r for r in resources if r.area == area]
    if kind:
        resources = [r for r in resources if r.kind == kind]
    resources = resources[:limit]

    if as_json:
        console.print_json(
            json.dumps([r.to_dict() for r in resources], default=str)
        )
        return

    table = Table(title="nemesis research library")
    table.add_column("Resource", style="bold cyan", max_width=42)
    table.add_column("Kind")
    table.add_column("Area")
    table.add_column("Why", max_width=52)

    for resource in resources:
        table.add_row(
            resource.title,
            resource.kind,
            resource.area,
            resource.note or resource.url,
        )

    console.print(table)
    coverage = LIBRARY_INDEX.coverage()
    console.print()
    console.print(f"[dim]{coverage['total']} resources across {coverage['areas']} "
                  f"capability areas.[/dim]")


# ----------------------------------------------------------------------
# The research workspace
# ----------------------------------------------------------------------
@app.command("lab")
def lab_command(
    action: str = typer.Argument(
        "status",
        help="init | note | finding | research | portfolio | status",
    ),
    title: str | None = typer.Argument(None, help="Title of the entry."),
    path: str | None = typer.Option(
        "./research-workspace", "--path", "-p", help="Workspace directory."
    ),
) -> None:
    """Manage the research workspace: notes, findings, projects, portfolio."""
    from .workspace import Workspace

    workspace = Workspace(root=Path(path))
    action = action.lower()

    if action == "init":
        created = workspace.create()
        console.print(f"[green]workspace ready[/green] at {workspace.root}")
        for item in created:
            console.print(f"  {item}")

    elif action in ("note", "finding", "research", "portfolio"):
        if not title:
            error_console.print("[red]A title is required.[/red]")
            raise typer.Exit(code=2) from None
        workspace.create()
        if action == "note":
            created = workspace.add_note(title)
        elif action == "finding":
            created = workspace.add_finding(title)
        elif action == "research":
            created = workspace.add_research(title)
        else:
            created = workspace.add_portfolio_entry(title)
        console.print(f"[green]wrote[/green] {created}")

    elif action == "status":
        workspace.create()
        inventory = workspace.inventory()
        console.print(f"[bold]workspace[/bold] {inventory['root']}")
        console.print()
        for name, count in inventory["counts"].items():
            console.print(f"  {name:<12} {count}")
        console.print()
        console.print(f"  {inventory['total']} entries in total")
        if inventory["tags"]:
            console.print(f"  tags: {', '.join(inventory['tags'])}")

    else:
        error_console.print(
            f"[red]Unknown action '{action}'.[/red] "
            f"Use init, note, finding, research, portfolio or status."
        )
        raise typer.Exit(code=2) from None


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
