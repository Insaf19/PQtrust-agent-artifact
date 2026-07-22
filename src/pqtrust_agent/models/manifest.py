"""Unsigned capability manifest payload model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.common import ResourceClass
from pqtrust_agent.models.profile import PROFILE_ID_RE

CAPABILITY_MANIFEST_HASH_DOMAIN = "PQTrust.CapabilityManifest.v1"
ProfileId = Annotated[str, Field(pattern=PROFILE_ID_RE)]


class CapabilityManifestPayload(BaseModel):
    """Unsigned capability manifest payload for future evidence signing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_version: Literal["1.0"] = Field(default="1.0", description="Manifest version.")
    agent_id: Annotated[str, Field(min_length=1, max_length=128)] = Field(
        description="Agent identifier."
    )
    key_id: Annotated[str, Field(min_length=1, max_length=128)] = Field(
        description="Manifest key identifier."
    )
    supported_profile_ids: tuple[ProfileId, ...] = Field(
        description="Sorted unique supported profile identifiers."
    )
    resource_class: ResourceClass = Field(description="Agent resource class.")
    max_handshake_bytes: Annotated[int | None, Field(default=None, gt=0, strict=True)] = Field(
        default=None,
        description="Optional positive handshake-byte capability bound.",
    )
    monotonic_version: Annotated[int, Field(gt=0, strict=True)] = Field(
        description="Monotonic manifest version."
    )
    issued_at: datetime = Field(description="UTC manifest issue time.")
    expires_at: datetime = Field(description="UTC manifest expiration time.")

    @field_validator("supported_profile_ids", mode="before")
    @classmethod
    def _reject_duplicate_profiles(cls, value: Any) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("supported_profile_ids must be a sequence")
        profile_ids = tuple(str(item) for item in value)
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("duplicate profile identifiers are not allowed")
        return tuple(
            sorted(
                profile_ids,
                key=lambda item: (int(item[1:]), item)
                if item[1:].isdigit()
                else (10**9, item),
            )
        )

    @field_validator("issued_at", "expires_at", mode="after")
    @classmethod
    def _normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetimes must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_expiry(self) -> CapabilityManifestPayload:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        return self

    def canonical_payload(self) -> object:
        """Return the JSON-compatible payload used for hashing and future signing."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes for this manifest payload."""

        return canonicalize(self)

    def manifest_hash(self) -> str:
        """Return the domain-separated manifest payload hash."""

        return domain_separated_sha256(CAPABILITY_MANIFEST_HASH_DOMAIN, self)
