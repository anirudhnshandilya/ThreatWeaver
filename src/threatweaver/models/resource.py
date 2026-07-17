from typing import Any

from pydantic import BaseModel, Field


class ResourceEvidence(BaseModel):
    """Source evidence associated with an infrastructure resource."""

    filename: str | None = None
    start_line: int | None = None
    end_line: int | None = None


class InfrastructureResource(BaseModel):
    """Normalized infrastructure resource."""

    address: str
    resource_type: str
    name: str
    provider: str | None = None
    values: dict[str, Any] = Field(default_factory=dict)
    evidence: ResourceEvidence | None = None
