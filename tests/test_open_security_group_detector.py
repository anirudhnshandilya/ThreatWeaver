from threatweaver.detectors.open_security_group import (
    OpenSecurityGroupDetector,
)
from threatweaver.findings.model import Severity
from threatweaver.models.resource import InfrastructureResource


def test_detect_unrestricted_security_group_ingress() -> None:
    resource = InfrastructureResource(
        address="aws_security_group.web",
        resource_type="aws_security_group",
        name="web",
        values={
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )

    detector = OpenSecurityGroupDetector()

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "TW-AWS-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource_address == "aws_security_group.web"
    assert findings[0].evidence["from_port"] == 22


def test_ignore_restricted_security_group_ingress() -> None:
    resource = InfrastructureResource(
        address="aws_security_group.internal",
        resource_type="aws_security_group",
        name="internal",
        values={
            "ingress": [
                {
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/8"],
                }
            ]
        },
    )

    detector = OpenSecurityGroupDetector()

    assert detector.detect(resource) == []


def test_ignore_non_security_group_resource() -> None:
    resource = InfrastructureResource(
        address="aws_instance.web",
        resource_type="aws_instance",
        name="web",
        values={
            "ingress": [
                {
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )

    detector = OpenSecurityGroupDetector()

    assert detector.detect(resource) == []


def test_detect_only_unrestricted_rules() -> None:
    resource = InfrastructureResource(
        address="aws_security_group.mixed",
        resource_type="aws_security_group",
        name="mixed",
        values={
            "ingress": [
                {
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/8"],
                },
                {
                    "from_port": 80,
                    "to_port": 80,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ]
        },
    )

    detector = OpenSecurityGroupDetector()

    findings = detector.detect(resource)

    assert len(findings) == 1
    assert findings[0].evidence["from_port"] == 80
