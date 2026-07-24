from threatweaver.detectors.public_ebs_snapshot import (
    PublicEBSSnapshotDetector,
)
from threatweaver.findings.model import Severity
from threatweaver.models.resource import InfrastructureResource


def test_public_ebs_snapshot_detected() -> None:
    detector = PublicEBSSnapshotDetector()

    resource = InfrastructureResource(
        address="aws_ebs_snapshot.database",
        resource_type="aws_ebs_snapshot",
        name="database",
        provider="aws",
        values={
            "public": True,
        },
    )

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "TW006"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].resource_address == "aws_ebs_snapshot.database"


def test_private_ebs_snapshot_not_detected() -> None:
    detector = PublicEBSSnapshotDetector()

    resource = InfrastructureResource(
        address="aws_ebs_snapshot.database",
        resource_type="aws_ebs_snapshot",
        name="database",
        provider="aws",
        values={
            "public": False,
        },
    )

    assert detector.detect(resource) == []


def test_snapshot_without_public_setting_not_detected() -> None:
    detector = PublicEBSSnapshotDetector()

    resource = InfrastructureResource(
        address="aws_ebs_snapshot.database",
        resource_type="aws_ebs_snapshot",
        name="database",
        provider="aws",
        values={},
    )

    assert detector.detect(resource) == []


def test_non_snapshot_resource_ignored() -> None:
    detector = PublicEBSSnapshotDetector()

    resource = InfrastructureResource(
        address="aws_ebs_volume.database",
        resource_type="aws_ebs_volume",
        name="database",
        provider="aws",
        values={
            "public": True,
        },
    )

    assert detector.detect(resource) == []
