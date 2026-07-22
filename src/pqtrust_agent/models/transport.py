"""Transport and execution-gate models for Stage 7."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.models.common import (
    ContractEvidenceMode,
    EndpointAuthenticationMode,
    FallbackRule,
    ResumptionRule,
)
from pqtrust_agent.models.compilation import ProfileId
from pqtrust_agent.models.protocol import SESSION_ID_RE, SHA256_HEX_RE
from pqtrust_agent.tls_groups import require_matching_tls_groups


class MessageType(StrEnum):
    DISCOVERY = "DISCOVERY"
    COMMITMENT = "COMMITMENT"
    REVEAL = "REVEAL"
    SELECTION_RESULT = "SELECTION_RESULT"
    UNSIGNED_CONTRACT = "UNSIGNED_CONTRACT"
    SIGNED_CONTRACT = "SIGNED_CONTRACT"
    CONFLICT_CERTIFICATE = "CONFLICT_CERTIFICATE"
    SAFE_ABORT = "SAFE_ABORT"
    TASK_REQUEST = "TASK_REQUEST"
    TASK_RESPONSE = "TASK_RESPONSE"
    SESSION_CLOSE = "SESSION_CLOSE"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"


class FrameHeader(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol_version: Literal["1.0"]
    message_type: MessageType
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    sequence_number: Annotated[int, Field(ge=0, strict=True)]
    payload_length: Annotated[int, Field(ge=0, strict=True)]
    payload_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]


class AuthorizedExecutionContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    selected_profile_id: ProfileId
    tls_group: Annotated[str, Field(min_length=1)]
    endpoint_authentication_mode: EndpointAuthenticationMode
    contract_evidence_mode: ContractEvidenceMode
    fallback_rule: FallbackRule
    resumption_rule: ResumptionRule
    activation_time: datetime
    contract_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]

    @field_validator("activation_time", mode="after")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("activation_time must be timezone-aware")
        return value.astimezone(UTC)

    def context_hash(self) -> str:
        return domain_separated_sha256("PQTrust.AuthorizedExecutionContext.v1", self)


class ExecutionGateRejection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    authorized: Literal[False] = False
    error_code: str
    message: str
    fail_closed: Literal[True] = True


class TlsExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    requested_tls_group: str
    negotiated_tls_group: str
    tls_version: str
    cipher_suite: str
    endpoint_authentication_result: str
    handshake_success: bool
    fallback_attempted: bool
    resumption_used: bool
    native_tls_invoked: bool

    @model_validator(mode="after")
    def _validate_success_binding(self) -> TlsExecutionResult:
        if self.handshake_success:
            require_matching_tls_groups(
                requested=self.requested_tls_group,
                negotiated=self.negotiated_tls_group,
            )
            if self.tls_version != "TLSv1.3":
                raise ValueError("Stage 7 TLS execution requires TLS 1.3")
            if self.fallback_attempted:
                raise ValueError("fallback is forbidden for successful Stage 7 evidence")
            if self.resumption_used:
                raise ValueError("unauthorized resumption is forbidden")
        return self


class TransportExecutionEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_version: Literal["1.0"] = "1.0"
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    scenario_id: str
    initiator_agent_id: str
    responder_agent_id: str
    discovery_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    transcript_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    selected_profile_id: ProfileId
    signed_contract_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    authorized_execution_context_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    requested_tls_group: str
    negotiated_tls_group: str
    tls_version: str
    cipher_suite: str
    endpoint_authentication_result: str
    handshake_success: bool
    fallback_attempted: bool
    resumption_used: bool
    task_request_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    task_response_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    state_transition_trace: tuple[str, ...]
    started_at: datetime
    completed_at: datetime
    transport_evidence_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]

    @field_validator("state_transition_trace", mode="before")
    @classmethod
    def _trace_tuple(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("state_transition_trace must be a sequence")
        return tuple(str(item) for item in value)

    @field_validator("started_at", "completed_at", mode="after")
    @classmethod
    def _time_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        return value.astimezone(UTC)

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("transport_evidence_hash", None)
        return payload

    def compute_transport_evidence_hash(self) -> str:
        return domain_separated_sha256("PQTrust.TransportExecutionEvidence.v1", self.hash_payload())
