"""Runtime state and discovery models for Stage 7."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.models.protocol import SHA256_HEX_RE


class RuntimeState(StrEnum):
    CREATED = "CREATED"
    DISCOVERY_COMPLETE = "DISCOVERY_COMPLETE"
    COMMITMENTS_REGISTERED = "COMMITMENTS_REGISTERED"
    REVEALS_VERIFIED = "REVEALS_VERIFIED"
    FEASIBILITY_EVALUATED = "FEASIBILITY_EVALUATED"
    PROFILE_SELECTED = "PROFILE_SELECTED"
    CONTRACT_CREATED = "CONTRACT_CREATED"
    CONTRACT_VERIFIED = "CONTRACT_VERIFIED"
    TLS_ACTIVATED = "TLS_ACTIVATED"
    TASK_EXECUTED = "TASK_EXECUTED"
    COMPLETED = "COMPLETED"
    CONFLICT_CERTIFIED = "CONFLICT_CERTIFIED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class StateTransitionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    from_state: RuntimeState
    to_state: RuntimeState
    reason: Annotated[str, Field(min_length=1, max_length=200)]


class AgentAdvertisement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    protocol_version: Literal["1.0"]
    manifest_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    supported_message_versions: tuple[Literal["1.0"], ...]
    endpoint_identifier: Annotated[str, Field(min_length=1, max_length=256)]
    evidence_key_fingerprint: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    valid_from: datetime
    valid_until: datetime

    @field_validator("supported_message_versions", mode="before")
    @classmethod
    def _versions_tuple(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("supported_message_versions must be a sequence")
        return tuple(value)

    @field_validator("valid_from", "valid_until", mode="after")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("advertisement times must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _valid_interval(self) -> AgentAdvertisement:
        if self.valid_until <= self.valid_from:
            raise ValueError("advertisement validity interval is invalid")
        return self


class DiscoveryResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol_version: Literal["1.0"] = "1.0"
    advertisements: tuple[AgentAdvertisement, ...]
    discovery_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]

    @field_validator("advertisements", mode="before")
    @classmethod
    def _ads_tuple(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("advertisements must be a sequence")
        return tuple(value)

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("discovery_hash", None)
        return payload

    def compute_discovery_hash(self) -> str:
        return domain_separated_sha256("PQTrust.AgentDiscovery.v1", self.hash_payload())


class RuntimeFailureEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    session_id: str
    runtime_state: RuntimeState
    phase: str
    error_code: str
    message: str
    requested_tls_group: str | None
    native_tls_invoked: bool
    task_execution_invoked: bool
    fail_closed: bool
    state_transition_trace: tuple[StateTransitionRecord, ...]
