import pytest

from threatweaver.parsers.terraform import (
    TerraformPlanError,
    extract_resources,
)


def test_extract_resources() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_instance.web",
                        "type": "aws_instance",
                        "name": "web",
                        "provider_name": ("registry.terraform.io/hashicorp/aws"),
                        "values": {
                            "instance_type": "t3.micro",
                            "public_ip": True,
                        },
                    },
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "values": {
                            "bucket": "example-logs",
                        },
                    },
                ]
            }
        }
    }

    resources = extract_resources(plan)

    assert len(resources) == 2

    instance = resources[0]
    assert instance.address == "aws_instance.web"
    assert instance.resource_type == "aws_instance"
    assert instance.name == "web"
    assert instance.values["public_ip"] is True

    bucket = resources[1]
    assert bucket.address == "aws_s3_bucket.logs"
    assert bucket.provider is None


def test_extract_resources_from_empty_plan() -> None:
    assert extract_resources({}) == []


def test_invalid_root_resources() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": {},
            }
        }
    }

    with pytest.raises(
        TerraformPlanError,
        match="resources must be a list",
    ):
        extract_resources(plan)


def test_invalid_resources_are_skipped() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    None,
                    {},
                    {
                        "address": "aws_instance.web",
                        "type": "aws_instance",
                        "name": "web",
                        "values": None,
                    },
                ]
            }
        }
    }

    resources = extract_resources(plan)

    assert len(resources) == 1
    assert resources[0].values == {}
