from pathlib import Path

import typer

from threatweaver.engine import DetectorEngine
from threatweaver.parsers.terraform import (
    extract_resources,
    load_terraform_plan,
)
from threatweaver.report import AnalysisReport

app = typer.Typer()

PLAN_PATH_ARGUMENT = typer.Argument(
    ...,
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
    help="Path to a Terraform plan JSON file.",
)


@app.callback()
def callback() -> None:
    """ThreatWeaver infrastructure security analysis."""


@app.command()
def analyze(
    path: Path = PLAN_PATH_ARGUMENT,
) -> None:
    """Analyze a Terraform plan for security risks."""

    typer.echo(f"Analyzing Terraform plan: {path}")

    plan = load_terraform_plan(path)
    resources = extract_resources(plan)

    engine = DetectorEngine()
    findings = engine.analyze(resources)
    report = AnalysisReport(findings=findings)

    typer.echo("")
    typer.echo(f"Resources analyzed: {len(resources)}")
    typer.echo(f"Findings: {report.total_findings}")
    typer.echo("")

    for finding in report.findings:
        typer.echo(f"{finding.severity.value.upper():8} {finding.rule_id}  {finding.title}")
        typer.echo(f"Resource: {finding.resource_address}")
        typer.echo(f"Recommendation: {finding.recommendation}")
        typer.echo("")

    typer.echo("Summary")
    typer.echo("-------")
    typer.echo(f"Critical: {report.critical_findings}")
    typer.echo(f"High:     {report.high_findings}")
    typer.echo(f"Medium:   {report.medium_findings}")
    typer.echo(f"Low:      {report.low_findings}")


def main() -> None:
    """Run the ThreatWeaver CLI."""
    app()


if __name__ == "__main__":
    main()
