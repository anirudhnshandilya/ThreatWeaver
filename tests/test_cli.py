import json
from pathlib import Path

from typer.testing import CliRunner

from threatweaver.cli import app

runner = CliRunner()


def test_analyze_empty_terraform_plan(tmp_path: Path) -> None:
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
