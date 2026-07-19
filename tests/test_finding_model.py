import pytest
from pydantic import ValidationError

from threatweaver.findings.model import SecurityFinding, Severity


def test_create_security_finding() -> None:
    finding = SecurityFinding(
        rule_id="TW-AWS-001",
        title="Public S3 bucket",
        description="The S3 bucket allows public access.",
        severity=Severity.HIGH,
        resource_address="aws_s3_bucket.example",
        evidence={
            "block_public_acls": False,
        },
        recommendation="Enable S3 public access blocking.",
    )

    assert finding.rule_id == "TW-AWS-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_address == "aws_s3_bucket.example"


def test_security_finding_defaults_to_empty_evidence() -> None:
    finding = SecurityFinding(
        rule_id="TW-AWS-002",
        title="Open security group",
        description="The security group permits unrestricted ingress.",
        severity=Severity.CRITICAL,
        resource_address="aws_security_group.web",
        recommendation="Restrict ingress to trusted CIDR ranges.",
    )

    assert finding.evidence == {}


def test_security_finding_accepts_string_severity() -> None:
    finding = SecurityFinding(
        rule_id="TW-AWS-003",
        title="Public instance",
        description="The instance has a public IP address.",
        severity="medium",
        resource_address="aws_instance.web",
        recommendation="Remove the public IP address.",
    )

    assert finding.severity == Severity.MEDIUM


def test_security_finding_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        SecurityFinding(
            rule_id="TW-AWS-004",
            title="Invalid finding",
            description="A finding with an unsupported severity.",
            severity="urgent",
            resource_address="aws_instance.invalid",
            recommendation="Use a supported severity.",
        )
