import json
from pathlib import Path

import pytest

from threatweaver.parsers.terraform import (
    TerraformPlanError,
    load_terraform_plan,
)


def test_load_terraform_plan(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    expected = {
        "format_version": "1.2",
        "terraform_version": "1.9.0",
    }

    plan_path.write_text(json.dumps(expected), encoding="utf-8")

    assert load_terraform_plan(plan_path) == expected


def test_missing_terraform_plan(tmp_path: Path) -> None:
    plan_path = tmp_path / "missing.json"

    with pytest.raises(TerraformPlanError, match="not found"):
        load_terraform_plan(plan_path)


def test_invalid_terraform_plan_json(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(TerraformPlanError, match="Invalid"):
        load_terraform_plan(plan_path)


def test_terraform_plan_must_be_object(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("[]", encoding="utf-8")

    with pytest.raises(TerraformPlanError, match="JSON object"):
        load_terraform_plan(plan_path)
