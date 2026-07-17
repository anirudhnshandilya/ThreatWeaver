import typer

app = typer.Typer(help="ThreatWeaver - Infrastructure Attack Path Analysis")


@app.command("version")
def version() -> None:
    """Show ThreatWeaver version."""
    typer.echo("ThreatWeaver 0.1.0")


@app.command("scan")
def scan() -> None:
    """Scan infrastructure (coming soon)."""
    typer.echo("🚧 Scan engine coming soon!")
