from __future__ import annotations

from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.models.resource import InfrastructureResource


class PublicS3BucketDetector:
    """Detect publicly accessible S3 buckets."""

    rule_id = "TW-AWS-002"

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:

        if resource.resource_type != "aws_s3_bucket":
            return []

        public = resource.values.get("public", False)

        if public is not True:
            return []

        return [
            SecurityFinding(
                rule_id=self.rule_id,
                title="Public S3 bucket",
                description=("The S3 bucket appears to be publicly accessible."),
                severity=Severity.HIGH,
                resource_address=resource.address,
                evidence={
                    "public": True,
                },
                recommendation=("Disable public access and enable Block Public Access."),
            )
        ]
