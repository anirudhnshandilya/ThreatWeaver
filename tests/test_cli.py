import json
from pathlib import Path

from typer.testing import CliRunner

from threatweaver.cli import app

runner = CliRunner()


def create_empty_plan(tmp_path: Path) -> Path:
    """Create an empty Terraform plan fixture."""

    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    return plan_path


def test_analyze_empty_terraform_plan(
    tmp_path: Path,
) -> None:
    plan_path = create_empty_plan(tmp_path)

    result = runner.invoke(
        app,
        ["analyze", str(plan_path)],
    )

    assert result.exit_code == 0
    assert "Resources analyzed: 0" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Critical: 0" in result.stdout
    assert "High:     0" in result.stdout
    assert "Medium:   0" in result.stdout
    assert "Low:      0" in result.stdout


def test_analyze_rejects_missing_plan() -> None:
    result = runner.invoke(
        app,
        ["analyze", "missing-plan.json"],
    )

    assert result.exit_code != 0


def test_analyze_outputs_json(
    tmp_path: Path,
) -> None:
    plan_path = create_empty_plan(tmp_path)

    result = runner.invoke(
        app,
        [
            "analyze",
            str(plan_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(result.stdout)

    assert payload["resources_analyzed"] == 0
    assert payload["summary"]["total"] == 0
    assert payload["summary"]["critical"] == 0
    assert payload["summary"]["high"] == 0
    assert payload["summary"]["medium"] == 0
    assert payload["summary"]["low"] == 0
    assert payload["findings"] == []


def test_analyze_writes_json_file(
    tmp_path: Path,
) -> None:
    plan_path = create_empty_plan(tmp_path)
    output_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            str(plan_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "Report written to:" in result.stdout

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["resources_analyzed"] == 0
    assert payload["summary"]["total"] == 0


def test_analyze_rejects_invalid_format(
    tmp_path: Path,
) -> None:
    plan_path = create_empty_plan(tmp_path)

    result = runner.invoke(
        app,
        [
            "analyze",
            str(plan_path),
            "--format",
            "xml",
        ],
    )

    assert result.exit_code != 0
    assert "Format must be either" in result.stderr
