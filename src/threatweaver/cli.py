import json
from pathlib import Path

import typer

from threatweaver.engine import DetectorEngine
from threatweaver.parsers.terraform import extract_resources, load_terraform_plan
from threatweaver.report import AnalysisReport
from threatweaver.sarif import export_sarif

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

FORMAT_OPTION = typer.Option(
    "text",
    "--format",
    "-f",
    help="Output format: text, json, or sarif.",
)

OUTPUT_OPTION = typer.Option(
    None,
    "--output",
    "-o",
    help="Write the report to a file.",
)


@app.callback()
def callback() -> None:
    """ThreatWeaver infrastructure security analysis."""


def render_text_report(
    resources_count: int,
    report: AnalysisReport,
) -> str:
    """Render an analysis report as human-readable text."""

    lines = [
        f"Resources analyzed: {resources_count}",
        f"Findings: {report.total_findings}",
        "",
    ]

    for finding in report.findings:
        lines.extend(
            [
                (f"{finding.severity.value.upper():8} {finding.rule_id}  {finding.title}"),
                f"Resource: {finding.resource_address}",
                f"Recommendation: {finding.recommendation}",
                "",
            ]
        )

    lines.extend(
        [
            "Summary",
            "-------",
            f"Critical: {report.critical_findings}",
            f"High:     {report.high_findings}",
            f"Medium:   {report.medium_findings}",
            f"Low:      {report.low_findings}",
        ]
    )

    return "\n".join(lines)


def render_json_report(
    resources_count: int,
    report: AnalysisReport,
) -> str:
    """Render an analysis report as JSON."""

    payload = {
        "resources_analyzed": resources_count,
        "summary": {
            "total": report.total_findings,
            "critical": report.critical_findings,
            "high": report.high_findings,
            "medium": report.medium_findings,
            "low": report.low_findings,
        },
        "findings": [finding.model_dump(mode="json") for finding in report.findings],
    }

    return json.dumps(payload, indent=2)


@app.command()
def analyze(
    path: Path = PLAN_PATH_ARGUMENT,
    output_format: str = FORMAT_OPTION,
    output: Path | None = OUTPUT_OPTION,
) -> None:
    """Analyze a Terraform plan for security risks."""

    plan = load_terraform_plan(path)
    resources = extract_resources(plan)

    engine = DetectorEngine()
    findings = engine.analyze(resources)
    report = AnalysisReport(findings=findings)

    normalized_format = output_format.lower()

    if normalized_format == "text":
        rendered_report = render_text_report(
            len(resources),
            report,
        )
    elif normalized_format == "json":
        rendered_report = render_json_report(
            len(resources),
            report,
        )
    elif normalized_format == "sarif":
        rendered_report = export_sarif(report)
    else:
        raise typer.BadParameter(
            "Format must be one of: text, json, sarif.",
            param_hint="--format",
        )

    if output is not None:
        output.write_text(
            rendered_report + "\n",
            encoding="utf-8",
        )
        typer.echo(f"Report written to: {output}")
        return

    typer.echo(rendered_report)


def main() -> None:
    """Run the ThreatWeaver CLI."""

    app()


if __name__ == "__main__":
    main()
