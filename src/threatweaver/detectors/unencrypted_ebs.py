from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.models.resource import InfrastructureResource


class UnencryptedEBSDetector:
    """Detect unencrypted EBS volumes."""

    RULE_ID = "TW005"

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:
        """Return findings for unencrypted EBS volumes."""

        if resource.resource_type != "aws_ebs_volume":
            return []

        if resource.values.get("encrypted") is True:
            return []

        return [
            SecurityFinding(
                rule_id=self.RULE_ID,
                title="Unencrypted EBS volume",
                description=("The EBS volume is not encrypted at rest."),
                severity=Severity.HIGH,
                resource_address=resource.address,
                recommendation=("Enable EBS encryption using an AWS KMS key."),
            )
        ]
