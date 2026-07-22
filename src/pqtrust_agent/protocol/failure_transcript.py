"""Commit-reveal failure transcripts for infeasible negotiations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.models.conflict import FeasibilityStatus
from pqtrust_agent.models.profile import PROFILE_ID_RE
from pqtrust_agent.models.protocol import (
    SESSION_ID_RE,
    SHA256_HEX_RE,
    NegotiationReveal,
    raw_commitment_hash,
)

FAILURE_TRANSCRIPT_HASH_DOMAIN = "PQTrust.NegotiationFailureTranscript.v1"
ProfileId = Annotated[str, Field(pattern=PROFILE_ID_RE)]
HashHex = Annotated[str, Field(pattern=SHA256_HEX_RE)]


class NegotiationFailureTranscript(BaseModel):
    """Immutable failure transcript binding reveals, infeasibility, certificate, and abort."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    transcript_version: Literal["1.0"] = "1.0"
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    initiator_commitment: HashHex
    responder_commitment: HashHex
    initiator_reveal: NegotiationReveal
    responder_reveal: NegotiationReveal
    initiator_proposal_hash: HashHex
    responder_proposal_hash: HashHex
    initiator_local_safe_set: tuple[ProfileId, ...]
    responder_local_safe_set: tuple[ProfileId, ...]
    common_safe_set: tuple[ProfileId, ...]
    feasibility_result: FeasibilityStatus
    conflict_certificate_hash: HashHex
    abort_record_hash: HashHex | None
    created_at: datetime
    transcript_hash: HashHex

    @field_validator(
        "initiator_local_safe_set",
        "responder_local_safe_set",
        "common_safe_set",
        mode="before",
    )
    @classmethod
    def _coerce_profiles(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("profile fields must be sequences")
        return tuple(str(item) for item in value)

    @field_validator("created_at", mode="after")
    @classmethod
    def _normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_commitments(self) -> NegotiationFailureTranscript:
        if self.initiator_reveal.proposal.session_id != self.session_id:
            raise ValueError("initiator reveal session mismatch")
        if self.responder_reveal.proposal.session_id != self.session_id:
            raise ValueError("responder reveal session mismatch")
        return self

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("transcript_hash", None)
        return payload

    def compute_transcript_hash(self) -> str:
        return domain_separated_sha256(FAILURE_TRANSCRIPT_HASH_DOMAIN, self.hash_payload())


def build_failure_transcript(
    *,
    session_id: str,
    initiator_reveal: NegotiationReveal,
    responder_reveal: NegotiationReveal,
    initiator_local_safe_set: tuple[str, ...],
    responder_local_safe_set: tuple[str, ...],
    common_safe_set: tuple[str, ...],
    conflict_certificate_hash: str,
    created_at: datetime,
    abort_record_hash: str | None = None,
) -> NegotiationFailureTranscript:
    transcript = NegotiationFailureTranscript(
        session_id=session_id,
        initiator_commitment=raw_commitment_hash(
            initiator_reveal.proposal.canonical_bytes(),
            initiator_reveal.nonce_bytes(),
        ),
        responder_commitment=raw_commitment_hash(
            responder_reveal.proposal.canonical_bytes(),
            responder_reveal.nonce_bytes(),
        ),
        initiator_reveal=initiator_reveal,
        responder_reveal=responder_reveal,
        initiator_proposal_hash=initiator_reveal.proposal.proposal_hash(),
        responder_proposal_hash=responder_reveal.proposal.proposal_hash(),
        initiator_local_safe_set=initiator_local_safe_set,
        responder_local_safe_set=responder_local_safe_set,
        common_safe_set=common_safe_set,
        feasibility_result=FeasibilityStatus.HARD_POLICY_CONFLICT,
        conflict_certificate_hash=conflict_certificate_hash,
        abort_record_hash=abort_record_hash,
        created_at=created_at,
        transcript_hash="0" * 64,
    )
    return transcript.model_copy(update={"transcript_hash": transcript.compute_transcript_hash()})


def attach_abort_hash(
    transcript: NegotiationFailureTranscript,
    abort_record_hash: str,
) -> NegotiationFailureTranscript:
    updated = transcript.model_copy(update={"abort_record_hash": abort_record_hash})
    return updated.model_copy(update={"transcript_hash": updated.compute_transcript_hash()})
