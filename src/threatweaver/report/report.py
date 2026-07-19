from __future__ import annotations

from pydantic import BaseModel, Field

from threatweaver.findings.model import SecurityFinding


class AnalysisReport(BaseModel):
    """Summary of a ThreatWeaver analysis run."""

    findings: list[SecurityFinding] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        return sum(finding.severity == "critical" for finding in self.findings)

    @property
    def high_findings(self) -> int:
        return sum(finding.severity == "high" for finding in self.findings)

    @property
    def medium_findings(self) -> int:
        return sum(finding.severity == "medium" for finding in self.findings)

    @property
    def low_findings(self) -> int:
        return sum(finding.severity == "low" for finding in self.findings)
