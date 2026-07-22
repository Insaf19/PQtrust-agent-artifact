"""Commit-reveal protocol models for Stage 5 negotiation transcripts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.compilation import ProfileId

SHA256_HEX_RE = r"^[0-9a-f]{64}$"
SESSION_ID_RE = r"^[0-9a-f]{64}$"
PROPOSAL_HASH_DOMAIN = "PQTrust.NegotiationProposal.v1"
TRANSCRIPT_HASH_DOMAIN = "PQTrust.NegotiationTranscript.v1"


def _profile_sort_key(profile_id: str) -> tuple[int, str]:
    suffix = profile_id[1:]
    return (int(suffix), profile_id) if suffix.isdigit() else (10**9, profile_id)


class NegotiationProposal(BaseModel):
    """Public selection input committed by one negotiation party."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol_version: Literal["1.0"] = "1.0"
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    agent_role: Literal["initiator", "responder"]
    scenario_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    task_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    catalog_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    manifest_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    policy_compilation_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    preference_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    cost_evidence_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    selector_implementation_version: Annotated[str, Field(min_length=1, max_length=32)]
    local_safe_profile_ids: tuple[ProfileId, ...]
    evaluation_time: datetime
    expires_at: datetime

    @field_validator("local_safe_profile_ids", mode="before")
    @classmethod
    def _coerce_safe_profiles(cls, value: Any) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("local_safe_profile_ids must be a sequence")
        profile_ids = tuple(str(item) for item in value)
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("local safe profiles must be unique")
        if profile_ids != tuple(sorted(profile_ids, key=_profile_sort_key)):
            raise ValueError("local safe profiles must be sorted")
        return profile_ids

    @field_validator("evaluation_time", "expires_at", mode="after")
    @classmethod
    def _normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("TIMEZONE_NAIVE: datetimes must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_expiry(self) -> NegotiationProposal:
        if self.expires_at <= self.evaluation_time:
            raise ValueError("INVALID_TIME_INTERVAL: expires_at must be later than evaluation_time")
        return self

    def canonical_payload(self) -> object:
        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        return canonicalize(self)

    def proposal_hash(self) -> str:
        return domain_separated_sha256(PROPOSAL_HASH_DOMAIN, self)


class NegotiationReveal(BaseModel):
    """Proposal plus caller-supplied 32-byte nonce revealed after commitments."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal: NegotiationProposal
    nonce_hex: Annotated[str, Field(pattern=SESSION_ID_RE)]

    def nonce_bytes(self) -> bytes:
        return bytes.fromhex(self.nonce_hex)

    def reveal_hash(self) -> str:
        return domain_separated_sha256("PQTrust.NegotiationReveal.v1", self)


class NegotiationTranscript(BaseModel):
    """Verifiable record binding both reveals and the recomputed selection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    transcript_version: Literal["1.0"] = "1.0"
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    initiator_commitment: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    responder_commitment: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    initiator_reveal: NegotiationReveal
    responder_reveal: NegotiationReveal
    initiator_local_safe_set: tuple[ProfileId, ...]
    responder_local_safe_set: tuple[ProfileId, ...]
    common_safe_set: tuple[ProfileId, ...]
    Pareto_frontier: tuple[ProfileId, ...]
    selected_profile_id: ProfileId
    selection_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    transcript_created_at: datetime
    transcript_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]

    @field_validator(
        "initiator_local_safe_set",
        "responder_local_safe_set",
        "common_safe_set",
        "Pareto_frontier",
        mode="before",
    )
    @classmethod
    def _coerce_profile_tuple(cls, value: Any) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("profile fields must be sequences")
        return tuple(str(item) for item in value)

    @field_validator("transcript_created_at", mode="after")
    @classmethod
    def _normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("TIMEZONE_NAIVE: transcript_created_at must be timezone-aware")
        return value.astimezone(UTC)

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("transcript_hash", None)
        return payload

    def canonical_payload(self) -> object:
        return to_json_compatible(self.hash_payload())

    def canonical_bytes(self) -> bytes:
        return canonicalize(self.hash_payload())

    def compute_transcript_hash(self) -> str:
        return domain_separated_sha256(TRANSCRIPT_HASH_DOMAIN, self.hash_payload())


def raw_commitment_hash(proposal_canonical_bytes: bytes, nonce_bytes: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(b"PQTrust.Commitment.v1")
    digest.update(b"\x00")
    digest.update(proposal_canonical_bytes)
    digest.update(nonce_bytes)
    return digest.hexdigest()
