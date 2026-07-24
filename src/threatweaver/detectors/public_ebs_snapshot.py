from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.models.resource import InfrastructureResource


class PublicEBSSnapshotDetector:
    """Detect publicly shared EBS snapshots."""

    RULE_ID = "TW006"

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:
        """Return a finding for a publicly shared EBS snapshot."""

        if resource.resource_type != "aws_ebs_snapshot":
            return []

        public = resource.values.get("public")

        if public is not True:
            return []

        return [
            SecurityFinding(
                rule_id=self.RULE_ID,
                title="Publicly shared EBS snapshot",
                description=(
                    "The EBS snapshot is publicly accessible and may expose "
                    "sensitive data to any AWS account."
                ),
                severity=Severity.CRITICAL,
                resource_address=resource.address,
                recommendation=(
                    "Remove public sharing and restrict snapshot permissions "
                    "to explicitly approved AWS accounts."
                ),
            )
        ]
