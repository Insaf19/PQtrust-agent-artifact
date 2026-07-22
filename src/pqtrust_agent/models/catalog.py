"""Trust-profile catalog model and YAML loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.evidence.yaml_loader import load_yaml_document
from pqtrust_agent.exceptions import CatalogValidationError
from pqtrust_agent.models.profile import TrustProfile

PROFILE_CATALOG_HASH_DOMAIN = "PQTrust.ProfileCatalog.v1"


class ProfileCatalog(BaseModel):
    """Versioned, deterministic trust-profile catalog."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    catalog_version: Literal["1.0"] = Field(description="Profile catalog schema version.")
    profiles: tuple[TrustProfile, ...] = Field(description="Canonical ordered profiles.")

    @field_validator("profiles", mode="before")
    @classmethod
    def _coerce_profiles_tuple(cls, value: Any) -> tuple[Any, ...]:
        if isinstance(value, list | tuple):
            return tuple(value)
        raise TypeError("profiles must be a sequence")

    @model_validator(mode="before")
    @classmethod
    def _sort_profiles(cls, data: Any) -> Any:
        if not isinstance(data, dict) or "profiles" not in data:
            return data
        profiles = data["profiles"]
        if not isinstance(profiles, list | tuple):
            return data
        copied = dict(data)
        copied["profiles"] = sorted(profiles, key=lambda item: item.get("profile_id", ""))
        return copied

    @model_validator(mode="after")
    def _validate_catalog(self) -> ProfileCatalog:
        if len(self.profiles) == 0:
            raise ValueError("profile catalog must not be empty")
        profile_ids = [profile.profile_id for profile in self.profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("profile IDs must be unique")
        tls_groups = [profile.tls_group for profile in self.profiles]
        if len(tls_groups) != len(set(tls_groups)):
            raise ValueError("TLS group identifiers must be unique")
        if tuple(profile_ids) != tuple(sorted(profile_ids, key=_profile_sort_key)):
            raise ValueError("profiles must be stored in canonical profile_id order")
        return self

    def get_profile(self, profile_id: str) -> TrustProfile:
        """Return a profile by identifier."""

        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise KeyError(profile_id)

    def profile_ids(self) -> tuple[str, ...]:
        """Return canonical profile identifiers."""

        return tuple(profile.profile_id for profile in self.profiles)

    def canonical_payload(self) -> object:
        """Return the JSON-compatible catalog payload."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes for this catalog."""

        return canonicalize(self)

    def catalog_hash(self) -> str:
        """Return the domain-separated catalog hash."""

        return domain_separated_sha256(PROFILE_CATALOG_HASH_DOMAIN, self)


def _profile_sort_key(profile_id: str) -> tuple[int, str]:
    suffix = profile_id[1:]
    return (int(suffix), profile_id) if suffix.isdigit() else (10**9, profile_id)


def load_profile_catalog(path: Path) -> ProfileCatalog:
    """Load and validate a trust-profile catalog from YAML."""

    try:
        raw = load_yaml_document(path)
        return ProfileCatalog.model_validate(raw)
    except Exception as exc:
        raise CatalogValidationError(str(exc)) from exc
