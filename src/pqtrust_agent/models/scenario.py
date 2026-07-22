"""Deterministic scenario definition model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.task import TaskDescriptor

SCENARIO_HASH_DOMAIN = "PQTrust.Scenario.v1"
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")]


class ScenarioDefinition(BaseModel):
    """A deterministic experimental scenario definition, not a measured result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_schema_version: Literal["1.0"] = "1.0"
    scenario_id: Identifier
    description: Annotated[str, Field(min_length=1, max_length=1200)]
    evaluation_time_utc: datetime
    task: TaskDescriptor
    initiator_agent_id: Identifier
    initiator_policy_id: Identifier
    responder_agent_id: Identifier
    responder_policy_id: Identifier

    @field_validator("evaluation_time_utc", mode="after")
    @classmethod
    def _normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation_time_utc must be timezone-aware")
        return value.astimezone(UTC)

    def canonical_payload(self) -> object:
        """Return the JSON-compatible scenario payload."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes."""

        return canonicalize(self)

    def scenario_hash(self) -> str:
        """Return the domain-separated scenario hash."""

        return domain_separated_sha256(SCENARIO_HASH_DOMAIN, self)
