"""Command-line interface for secops-triage."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from secops_triage.parsers import zeek

console = Console()
err = Console(stderr=True)  # progress and warnings go to stderr; data goes to stdout

PARSERS = {
    "conn.log": zeek.extract_from_conn,
    "dns.log": zeek.extract_from_dns,
    "ssl.log": zeek.extract_from_ssl,
}
LOG_DIR = click.Path(exists=True, file_okay=False, path_type=Path)


@click.group()
@click.version_option(package_name="secops-triage")
def main() -> None:
    """Triage tooling for network telemetry."""


@main.command()
@click.argument("log_dir", type=LOG_DIR)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
@click.option("--top", default=20, show_default=True, help="How many results to show.")
@click.option(
    "--type",
    "type_filter",
    type=click.Choice(["ipv4", "ipv6", "domain"]),
    help="Only show indicators of this type.",
)
def parse(log_dir: Path, as_json: bool, top: int, type_filter: str | None) -> None:
    """Extract indicators from a directory of Zeek JSON logs."""
    counts: Counter[tuple[str, str, str]] = Counter()
    stats = zeek.ReadStats()
    for filename, parser in PARSERS.items():
        path = log_dir / filename
        if path.exists():
            for ind in parser(path, stats):
                if type_filter and ind.type != type_filter:
                    continue
                counts[(ind.value, ind.type.value, ind.source)] += 1

    if stats.skipped:
        msg = f"skipped {stats.skipped} of {stats.lines} lines (not JSON records)"
        err.print(f"[yellow]{msg}[/yellow]")

    if as_json:
        payload = [
            {"value": v, "type": t, "source": s, "count": n}
            for (v, t, s), n in counts.most_common(top)
        ]
        click.echo(json.dumps(payload, indent=2))
        return

    table = Table(title=f"Indicators from {log_dir}")
    table.add_column("Value", overflow="fold")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Count", justify="right")
    for (value, type_, source), n in counts.most_common(top):
        # Log values are untrusted input: escape them so they print as plain
        # text, never as Rich markup that could restyle or hide output.
        table.add_row(escape(value), type_, source, str(n))
    console.print(table)
    console.print(f"[dim]{len(counts)} unique indicators total[/dim]")
