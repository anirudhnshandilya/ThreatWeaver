from __future__ import annotations

from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.models.resource import InfrastructureResource


class OpenSecurityGroupDetector:
    """Detect AWS security groups permitting unrestricted ingress."""

    rule_id = "TW-AWS-001"

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:
        """Return findings for unrestricted security-group ingress."""

        if resource.resource_type != "aws_security_group":
            return []

        ingress_rules = resource.values.get("ingress", [])

        if not isinstance(ingress_rules, list):
            return []

        findings: list[SecurityFinding] = []

        for ingress in ingress_rules:
            if not isinstance(ingress, dict):
                continue

            cidr_blocks = ingress.get("cidr_blocks", [])

            if not isinstance(cidr_blocks, list):
                continue

            if "0.0.0.0/0" not in cidr_blocks:
                continue

            findings.append(
                SecurityFinding(
                    rule_id=self.rule_id,
                    title="Unrestricted security group ingress",
                    description=(
                        "The security group permits inbound traffic from any IPv4 address."
                    ),
                    severity=Severity.HIGH,
                    resource_address=resource.address,
                    evidence={
                        "cidr_blocks": cidr_blocks,
                        "from_port": ingress.get("from_port"),
                        "to_port": ingress.get("to_port"),
                        "protocol": ingress.get("protocol"),
                    },
                    recommendation=(
                        "Restrict ingress to trusted CIDR ranges and only required ports."
                    ),
                )
            )

        return findings
