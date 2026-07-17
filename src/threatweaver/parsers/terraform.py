import json
from pathlib import Path
from typing import Any

from threatweaver.models.resource import InfrastructureResource


class TerraformPlanError(Exception):
    """Raised when a Terraform plan file cannot be parsed."""


def load_terraform_plan(path: Path) -> dict[str, Any]:
    """Load and validate a Terraform plan JSON file."""

    if not path.exists():
        raise TerraformPlanError(f"Terraform plan not found: {path}")

    if not path.is_file():
        raise TerraformPlanError(f"Terraform plan path is not a file: {path}")

    try:
        with path.open(encoding="utf-8") as plan_file:
            data = json.load(plan_file)
    except json.JSONDecodeError as exc:
        raise TerraformPlanError(f"Invalid Terraform plan JSON: {path}") from exc

    if not isinstance(data, dict):
        raise TerraformPlanError("Terraform plan must contain a JSON object.")

    return data


def extract_resources(
    plan: dict[str, Any],
) -> list[InfrastructureResource]:
    """Extract normalized resources from Terraform plan JSON."""

    planned_values = plan.get("planned_values", {})
    root_module = planned_values.get("root_module", {})

    raw_resources = root_module.get("resources", [])

    if not isinstance(raw_resources, list):
        raise TerraformPlanError("Terraform root module resources must be a list.")

    resources: list[InfrastructureResource] = []

    for raw_resource in raw_resources:
        if not isinstance(raw_resource, dict):
            continue

        address = raw_resource.get("address")
        resource_type = raw_resource.get("type")
        name = raw_resource.get("name")

        if not all(isinstance(value, str) for value in (address, resource_type, name)):
            continue

        values = raw_resource.get("values", {})

        if not isinstance(values, dict):
            values = {}

        provider = raw_resource.get("provider_name")

        if not isinstance(provider, str):
            provider = None

        resources.append(
            InfrastructureResource(
                address=address,
                resource_type=resource_type,
                name=name,
                provider=provider,
                values=values,
            )
        )

    return resources
