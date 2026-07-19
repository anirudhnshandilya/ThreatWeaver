from threatweaver.detectors.public_s3_bucket import (
    PublicS3BucketDetector,
)
from threatweaver.findings.model import Severity
from threatweaver.models.resource import InfrastructureResource


def test_detect_public_bucket() -> None:
    resource = InfrastructureResource(
        address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        name="logs",
        values={
            "public": True,
        },
    )

    detector = PublicS3BucketDetector()

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "TW-AWS-002"
    assert findings[0].severity == Severity.HIGH


def test_ignore_private_bucket() -> None:
    resource = InfrastructureResource(
        address="aws_s3_bucket.private",
        resource_type="aws_s3_bucket",
        name="private",
        values={
            "public": False,
        },
    )

    detector = PublicS3BucketDetector()

    assert detector.detect(resource) == []


def test_ignore_other_resources() -> None:
    resource = InfrastructureResource(
        address="aws_instance.web",
        resource_type="aws_instance",
        name="web",
        values={
            "public": True,
        },
    )

    detector = PublicS3BucketDetector()

    assert detector.detect(resource) == []
