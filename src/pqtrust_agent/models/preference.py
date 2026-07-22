"""Agent cost-preference model for selector-stage negotiation."""

from __future__ import annotations

from os import PathLike
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pqtrust_agent.evidence.canonical import canonicalize, domain_separated_sha256
from pqtrust_agent.evidence.yaml_loader import load_yaml_model

PREFERENCE_HASH_DOMAIN = "PQTrust.AgentCostPreference.v1"
BasisPoints = Annotated[int, Field(ge=0, le=10000, strict=True)]


class AgentCostPreference(BaseModel):
    """Frozen integer-basis-point preference declaration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    preference_schema_version: Literal["1.0"] = "1.0"
    preference_id: Annotated[str, Field(min_length=1, max_length=128)]
    preference_version: Annotated[int, Field(gt=0, strict=True)]
    agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    wall_time_weight_bps: BasisPoints
    process_cpu_time_weight_bps: BasisPoints
    total_handshake_bytes_weight_bps: BasisPoints
    description: Annotated[str, Field(min_length=1, max_length=1200)]

    @model_validator(mode="after")
    def _validate_weight_sum(self) -> AgentCostPreference:
        total = (
            self.wall_time_weight_bps
            + self.process_cpu_time_weight_bps
            + self.total_handshake_bytes_weight_bps
        )
        if total != 10000:
            raise ValueError("preference weights must sum to 10000 basis points")
        return self

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical preference bytes."""

        return canonicalize(self)

    def preference_hash(self) -> str:
        """Return the domain-separated preference hash."""

        return domain_separated_sha256(PREFERENCE_HASH_DOMAIN, self)


def load_agent_cost_preference(path: str | PathLike[str]) -> AgentCostPreference:
    """Load an agent cost preference from duplicate-key-safe YAML."""

    from pathlib import Path

    return load_yaml_model(Path(path), AgentCostPreference)
