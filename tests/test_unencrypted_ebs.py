from threatweaver.detectors.unencrypted_ebs import (
    UnencryptedEBSDetector,
)
from threatweaver.findings.model import Severity
from threatweaver.models.resource import InfrastructureResource


def test_unencrypted_ebs_detected() -> None:
    detector = UnencryptedEBSDetector()

    resource = InfrastructureResource(
        address="aws_ebs_volume.data",
        resource_type="aws_ebs_volume",
        name="data",
        provider="aws",
        values={
            "encrypted": False,
        },
    )

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "TW005"
    assert findings[0].severity == Severity.HIGH


def test_encrypted_ebs_not_detected() -> None:
    detector = UnencryptedEBSDetector()

    resource = InfrastructureResource(
        address="aws_ebs_volume.data",
        resource_type="aws_ebs_volume",
        name="data",
        provider="aws",
        values={
            "encrypted": True,
        },
    )

    assert detector.detect(resource) == []


def test_non_ebs_resource_ignored() -> None:
    detector = UnencryptedEBSDetector()

    resource = InfrastructureResource(
        address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        name="logs",
        provider="aws",
        values={},
    )

    assert detector.detect(resource) == []
