from __future__ import annotations

from typing import Protocol

from threatweaver.detectors import (
    OpenSecurityGroupDetector,
    PublicEC2InstanceDetector,
    PublicS3BucketDetector,
)
from threatweaver.detectors.public_rds_detector import PublicRDSDetector
from threatweaver.detectors.unencrypted_ebs import (
    UnencryptedEBSDetector,
)
from threatweaver.findings.model import SecurityFinding
from threatweaver.models.resource import InfrastructureResource


class Detector(Protocol):
    """Interface implemented by security detectors."""

    def detect(
        self,
        resource: InfrastructureResource,
    ) -> list[SecurityFinding]:
        """Analyze one infrastructure resource."""
        ...


class DetectorEngine:
    """Run all ThreatWeaver detectors."""

    def __init__(self) -> None:
        self.detectors: list[Detector] = [
            OpenSecurityGroupDetector(),
            PublicS3BucketDetector(),
            PublicEC2InstanceDetector(),
            PublicRDSDetector(),
            UnencryptedEBSDetector(),
        ]

    def analyze(
        self,
        resources: list[InfrastructureResource],
    ) -> list[SecurityFinding]:
        """Run every detector against every resource."""

        findings: list[SecurityFinding] = []

        for resource in resources:
            for detector in self.detectors:
                findings.extend(detector.detect(resource))

        return findings
