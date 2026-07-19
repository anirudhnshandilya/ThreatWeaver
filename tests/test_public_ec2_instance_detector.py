from threatweaver.detectors.public_ec2_instance import (
    PublicEC2InstanceDetector,
)
from threatweaver.findings.model import Severity
from threatweaver.models.resource import InfrastructureResource


def test_detect_public_ec2_instance() -> None:
    resource = InfrastructureResource(
        address="aws_instance.web",
        resource_type="aws_instance",
        name="web",
        values={
            "associate_public_ip_address": True,
        },
    )

    detector = PublicEC2InstanceDetector()

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "TW-AWS-003"
    assert findings[0].severity == Severity.MEDIUM


def test_ignore_private_instance() -> None:
    resource = InfrastructureResource(
        address="aws_instance.internal",
        resource_type="aws_instance",
        name="internal",
        values={
            "associate_public_ip_address": False,
        },
    )

    detector = PublicEC2InstanceDetector()

    assert detector.detect(resource) == []


def test_ignore_other_resource_types() -> None:
    resource = InfrastructureResource(
        address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        name="logs",
        values={
            "associate_public_ip_address": True,
        },
    )

    detector = PublicEC2InstanceDetector()

    assert detector.detect(resource) == []
