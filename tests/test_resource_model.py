from threatweaver.models.resource import (
    InfrastructureResource,
    ResourceEvidence,
)


def test_infrastructure_resource() -> None:
    resource = InfrastructureResource(
        address="aws_instance.web",
        resource_type="aws_instance",
        name="web",
        provider="registry.terraform.io/hashicorp/aws",
        values={
            "instance_type": "t3.micro",
            "public_ip": True,
        },
    )

    assert resource.address == "aws_instance.web"
    assert resource.resource_type == "aws_instance"
    assert resource.name == "web"
    assert resource.values["public_ip"] is True


def test_resource_default_values() -> None:
    resource = InfrastructureResource(
        address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        name="logs",
    )

    assert resource.values == {}
    assert resource.provider is None
    assert resource.evidence is None


def test_resource_evidence() -> None:
    evidence = ResourceEvidence(
        filename="main.tf",
        start_line=10,
        end_line=18,
    )

    resource = InfrastructureResource(
        address="aws_security_group.web",
        resource_type="aws_security_group",
        name="web",
        evidence=evidence,
    )

    assert resource.evidence is not None
    assert resource.evidence.filename == "main.tf"
    assert resource.evidence.start_line == 10
