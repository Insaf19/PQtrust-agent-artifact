"""Trust contract models and canonical hashes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.common import (
    ContractEvidenceMode,
    EndpointAuthenticationMode,
    EvidenceAlgorithm,
    FallbackRule,
    LeaseStrictness,
    ResumptionRule,
    canonical_evidence_algorithm,
)
from pqtrust_agent.models.compilation import ProfileId
from pqtrust_agent.models.protocol import SESSION_ID_RE, SHA256_HEX_RE

UNSIGNED_CONTRACT_HASH_DOMAIN = "PQTrust.UnsignedTrustContract.v1"
SIGNED_CONTRACT_HASH_DOMAIN = "PQTrust.SignedTrustContract.v1"


class UnsignedTrustContract(BaseModel):
    """Unsigned contract payload signed independently by both agents."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_version: Literal["1.0"] = "1.0"
    contract_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    initiator_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    responder_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    scenario_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    task_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    catalog_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    cost_evidence_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    initiator_manifest_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    responder_manifest_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    initiator_policy_compilation_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    responder_policy_compilation_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    initiator_preference_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    responder_preference_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    transcript_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    selection_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    common_safe_profile_ids: tuple[ProfileId, ...]
    Pareto_frontier_profile_ids: tuple[ProfileId, ...]
    selected_profile_id: ProfileId
    tls_group: Annotated[str, Field(min_length=1)]
    endpoint_authentication_mode: EndpointAuthenticationMode
    contract_evidence_mode: ContractEvidenceMode
    fallback_rule: FallbackRule
    resumption_rule: ResumptionRule
    lease_strictness: LeaseStrictness
    issued_at: datetime
    expires_at: datetime

    @field_validator("common_safe_profile_ids", "Pareto_frontier_profile_ids", mode="before")
    @classmethod
    def _coerce_profile_tuple(cls, value: Any) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("profile fields must be sequences")
        return tuple(str(item) for item in value)

    @field_validator("issued_at", "expires_at", mode="after")
    @classmethod
    def _normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("TIMEZONE_NAIVE: contract datetimes must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_interval(self) -> UnsignedTrustContract:
        if self.expires_at <= self.issued_at:
            raise ValueError("INVALID_TIME_INTERVAL: expires_at must be later than issued_at")
        if self.initiator_agent_id == self.responder_agent_id:
            raise ValueError("contract agents must be distinct")
        return self

    def canonical_payload(self) -> object:
        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        return canonicalize(self)

    def contract_payload_hash(self) -> str:
        return domain_separated_sha256(UNSIGNED_CONTRACT_HASH_DOMAIN, self)


class AgentContractSignature(BaseModel):
    """One party's signature and public-key binding metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    role: Literal["initiator", "responder"]
    key_id: Annotated[str, Field(min_length=1, max_length=160)]
    algorithm: EvidenceAlgorithm
    public_key_sha256: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    signature_base64: Annotated[str, Field(min_length=1)]

    @field_validator("algorithm", mode="before")
    @classmethod
    def _coerce_algorithm(cls, value: Any) -> EvidenceAlgorithm:
        return canonical_evidence_algorithm(str(value))


class SignedTrustContract(BaseModel):
    """Contract payload plus independent initiator and responder signatures."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    unsigned_contract: UnsignedTrustContract
    initiator_signature: AgentContractSignature
    responder_signature: AgentContractSignature
    signed_contract_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]

    @model_validator(mode="after")
    def _validate_roles(self) -> SignedTrustContract:
        if self.initiator_signature.role != "initiator":
            raise ValueError("initiator signature role mismatch")
        if self.responder_signature.role != "responder":
            raise ValueError("responder signature role mismatch")
        if self.initiator_signature.agent_id == self.responder_signature.agent_id:
            raise ValueError("signature agents must be distinct")
        return self

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("signed_contract_hash", None)
        return payload

    def compute_signed_contract_hash(self) -> str:
        return domain_separated_sha256(SIGNED_CONTRACT_HASH_DOMAIN, self.hash_payload())
