"""Stage 6 safe-abort models."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.models.protocol import SESSION_ID_RE, SHA256_HEX_RE

ABORT_HASH_DOMAIN = "PQTrust.SafeAbortRecord.v1"
ABORT_ID_DOMAIN = b"PQTrust.SafeAbortID.v1\x00"
HashHex = Annotated[str, Field(pattern=SHA256_HEX_RE)]


class SafeAbortRecord(BaseModel):
    """Immutable fail-closed abort record for infeasible sessions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    abort_version: Literal["1.0"] = "1.0"
    abort_id: HashHex
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    scenario_hash: HashHex
    conflict_certificate_hash: HashHex
    failure_transcript_hash: HashHex
    abort_reason_code: str
    fallback_attempted: Literal[False] = False
    selected_profile_id: None = None
    contract_created: Literal[False] = False
    issued_at: datetime
    abort_hash: HashHex

    @field_validator("issued_at", mode="after")
    @classmethod
    def _normalize_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_fail_closed(self) -> SafeAbortRecord:
        if self.selected_profile_id is not None:
            raise ValueError("abort record cannot select a profile")
        if self.contract_created:
            raise ValueError("abort record cannot create a trust contract")
        if self.fallback_attempted:
            raise ValueError("abort record cannot attempt fallback")
        return self

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("abort_hash", None)
        return payload

    def compute_abort_hash(self) -> str:
        return domain_separated_sha256(ABORT_HASH_DOMAIN, self.hash_payload())


def abort_id_for(session_id: str, conflict_certificate_hash: str) -> str:
    digest = hashlib.sha256()
    digest.update(ABORT_ID_DOMAIN)
    digest.update(bytes.fromhex(session_id))
    digest.update(bytes.fromhex(conflict_certificate_hash))
    return digest.hexdigest()
