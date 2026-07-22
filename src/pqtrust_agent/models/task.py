"""Task descriptor model for public canonical context."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.common import (
    ConfidentialityHorizon,
    NetworkClass,
    OperationalImpact,
    TaskSensitivity,
)

TASK_DESCRIPTOR_HASH_DOMAIN = "PQTrust.TaskDescriptor.v1"
PolicyClass = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")]


class TaskDescriptor(BaseModel):
    """Public canonical task context ``x = (s, i, h, d, l, n, o)``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    descriptor_version: Literal["1.0"] = Field(
        default="1.0",
        description="Task descriptor schema version.",
    )
    sensitivity: TaskSensitivity = Field(description="Task sensitivity class.")
    operational_impact: OperationalImpact = Field(description="Task operational impact.")
    confidentiality_horizon: ConfidentialityHorizon = Field(
        description="Required confidentiality horizon."
    )
    delegation_depth: Annotated[int, Field(ge=0, le=8, strict=True)] = Field(
        description="Permitted delegation depth from 0 to 8."
    )
    expected_session_seconds: Annotated[int, Field(ge=1, le=86400, strict=True)] = Field(
        description="Expected session duration in seconds."
    )
    network_class: NetworkClass = Field(description="Expected network class.")
    organization_policy_class: PolicyClass = Field(description="Organization policy class.")

    def canonical_payload(self) -> object:
        """Return the JSON-compatible payload used for hashing and future signing."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes for this descriptor."""

        return canonicalize(self)

    def context_hash(self) -> str:
        """Return the domain-separated task-context hash."""

        return domain_separated_sha256(TASK_DESCRIPTOR_HASH_DOMAIN, self)
