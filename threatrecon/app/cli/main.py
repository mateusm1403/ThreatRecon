from __future__ import annotations

import asyncio
from dataclasses import replace

import typer
from loguru import logger

from threatrecon.app.core.config import Settings
from threatrecon.app.core.logging import configure_logging
from threatrecon.app.orchestrator.scan_orchestrator import ScanOrchestrator
from threatrecon.app.storage.sqlite_store import SQLiteStore


app = typer.Typer(
    name="threatrecon",
    help="Passive OSINT, automated reconnaissance, and attack surface mapping.",
    no_args_is_help=True,
)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain, for example example.com"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logs."),
    max_pages: int | None = typer.Option(None, "--max-pages", help="Override THREATRECON_MAX_PAGES."),
    no_crtsh: bool = typer.Option(False, "--no-crtsh", help="Disable passive crt.sh lookup."),
) -> None:
    """Run a passive scan and generate HTML, CSV, and JSON outputs."""
    configure_logging(verbose)
    settings = Settings.from_env()
    if max_pages is not None:
        settings = replace(settings, max_pages=max_pages)
    if no_crtsh:
        settings = replace(settings, enable_crtsh=False)

    try:
        result = asyncio.run(ScanOrchestrator(settings).run(domain))
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        raise typer.Exit(code=130) from None
    except Exception as exc:
        logger.exception("Scan failed: {}", exc)
        raise typer.Exit(code=1) from exc

    typer.echo("")
    typer.echo(f"Exposure score: {result.exposure_score}/100")
    typer.echo(f"Findings: {len(result.findings)}")
    if result.artifacts:
        typer.echo(f"HTML report: {result.artifacts.html_report}")
        typer.echo(f"CSV export:   {result.artifacts.csv_path}")
        typer.echo(f"JSON export:  {result.artifacts.json_path}")


@app.command()
def history(
    domain: str | None = typer.Argument(None, help="Optional domain filter."),
    limit: int = typer.Option(10, "--limit", "-n", help="Number of scans to show."),
) -> None:
    """Show recent scan history from SQLite."""
    configure_logging(False)
    store = SQLiteStore(Settings.from_env().database_path)
    rows = store.list_scans(domain=domain, limit=limit)
    if not rows:
        typer.echo("No scans found.")
        return

    for row in rows:
        typer.echo(
            f"#{row['id']} {row['domain']} | score={row['exposure_score']} | completed={row['completed_at']}"
        )
