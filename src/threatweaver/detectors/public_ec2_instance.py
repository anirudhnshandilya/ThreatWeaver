from __future__ import annotations

from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.models.resource import InfrastructureResource


class PublicEC2InstanceDetector:
    """Detect EC2 instances with public IP addresses."""

    rule_id = "TW-AWS-003"

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:
        if resource.resource_type != "aws_instance":
            return []

        associate_public_ip = resource.values.get(
            "associate_public_ip_address",
            False,
        )

        if associate_public_ip is not True:
            return []

        return [
            SecurityFinding(
                rule_id=self.rule_id,
                title="Public EC2 instance",
                description=("The EC2 instance is configured with a public IP address."),
                severity=Severity.MEDIUM,
                resource_address=resource.address,
                evidence={
                    "associate_public_ip_address": True,
                },
                recommendation=(
                    "Avoid assigning public IPs unless internet access is required. "
                    "Prefer private subnets with a NAT Gateway or load balancer."
                ),
            )
        ]
