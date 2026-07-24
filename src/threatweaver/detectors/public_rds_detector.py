from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.models.resource import InfrastructureResource


class PublicRDSDetector:
    """Detect publicly accessible Amazon RDS instances."""

    RULE_ID = "TW004"

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:
        """Return a finding for a publicly accessible RDS instance."""

        if resource.resource_type != "aws_db_instance":
            return []

        if resource.values.get("publicly_accessible") is not True:
            return []

        return [
            SecurityFinding(
                rule_id=self.RULE_ID,
                title="Publicly accessible RDS instance",
                description=(
                    "The Amazon RDS database instance is configured to be publicly accessible."
                ),
                severity=Severity.HIGH,
                resource_address=resource.address,
                recommendation=(
                    "Disable public accessibility and place the database "
                    "in private subnets with restricted network access."
                ),
            )
        ]
