from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Supported security finding severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityFinding(BaseModel):
    """A structured security finding produced by ThreatWeaver."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_address: str
    evidence: dict[str, object] = Field(default_factory=dict)
    recommendation: str
