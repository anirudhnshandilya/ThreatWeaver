from threatweaver.detectors.public_rds_detector import PublicRDSDetector
from threatweaver.findings.model import Severity
from threatweaver.models.resource import InfrastructureResource


def test_public_rds_detected() -> None:
    detector = PublicRDSDetector()

    resource = InfrastructureResource(
        address="aws_db_instance.prod",
        resource_type="aws_db_instance",
        name="prod",
        provider="aws",
        values={
            "publicly_accessible": True,
        },
    )

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "TW004"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource_address == "aws_db_instance.prod"


def test_private_rds_not_detected() -> None:
    detector = PublicRDSDetector()

    resource = InfrastructureResource(
        address="aws_db_instance.prod",
        resource_type="aws_db_instance",
        name="prod",
        provider="aws",
        values={
            "publicly_accessible": False,
        },
    )

    assert detector.detect(resource) == []


def test_rds_without_public_setting_not_detected() -> None:
    detector = PublicRDSDetector()

    resource = InfrastructureResource(
        address="aws_db_instance.prod",
        resource_type="aws_db_instance",
        name="prod",
        provider="aws",
        values={},
    )

    assert detector.detect(resource) == []


def test_other_resources_ignored() -> None:
    detector = PublicRDSDetector()

    resource = InfrastructureResource(
        address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        name="logs",
        provider="aws",
        values={
            "publicly_accessible": True,
        },
    )

    assert detector.detect(resource) == []
