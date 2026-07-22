"""Stage 6 conflict certificate models."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import domain_separated_sha256, to_json_compatible
from pqtrust_agent.models.profile import PROFILE_ID_RE
from pqtrust_agent.models.protocol import SESSION_ID_RE, SHA256_HEX_RE

CONSTRAINT_HASH_DOMAIN = "PQTrust.NamedConstraint.v1"
CERTIFICATE_HASH_DOMAIN = "PQTrust.MinimalConflictCertificate.v1"
CERTIFICATE_ID_DOMAIN = b"PQTrust.MinimalConflictCertificateID.v1\x00"
SHRINKING_ALGORITHM_VERSION: Literal["deletion-ius-v1"] = "deletion-ius-v1"

ProfileId = Annotated[str, Field(pattern=PROFILE_ID_RE)]
HashHex = Annotated[str, Field(pattern=SHA256_HEX_RE)]


class ConstraintSourceType(StrEnum):
    MANIFEST = "manifest"
    PRIVATE_POLICY = "private_policy"
    TASK = "task"
    TRUST_PROFILE = "trust_profile"
    PROTOCOL = "protocol"


class FeasibilityStatus(StrEnum):
    FEASIBLE = "feasible"
    EMPTY_BILATERAL_PROFILE_INTERSECTION = "empty_bilateral_profile_intersection"
    HARD_POLICY_CONFLICT = "hard_policy_conflict"
    EXPIRED_OR_INVALID_EVIDENCE = "expired_or_invalid_evidence"
    MALFORMED_NEGOTIATION_INPUT = "malformed_negotiation_input"
    PROTOCOL_INTEGRITY_FAILURE = "protocol_integrity_failure"


class ConflictCategory(StrEnum):
    NO_COMMON_PROFILE = "NO_COMMON_PROFILE"
    ASSURANCE_FLOOR_CONFLICT = "ASSURANCE_FLOOR_CONFLICT"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    ENDPOINT_AUTHENTICATION_CONFLICT = "ENDPOINT_AUTHENTICATION_CONFLICT"
    TLS_GROUP_CONFLICT = "TLS_GROUP_CONFLICT"
    CONTRACT_EVIDENCE_CONFLICT = "CONTRACT_EVIDENCE_CONFLICT"
    FALLBACK_POLICY_CONFLICT = "FALLBACK_POLICY_CONFLICT"
    RESUMPTION_POLICY_CONFLICT = "RESUMPTION_POLICY_CONFLICT"
    LEASE_CONFLICT = "LEASE_CONFLICT"
    RESOURCE_LIMIT_CONFLICT = "RESOURCE_LIMIT_CONFLICT"
    MULTI_CAUSE_CONFLICT = "MULTI_CAUSE_CONFLICT"


class NamedConstraint(BaseModel):
    """A typed, canonically serializable hard negotiation constraint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    constraint_id: Annotated[str, Field(min_length=1, max_length=192)]
    source_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_type: ConstraintSourceType
    category: Annotated[str, Field(min_length=1, max_length=96)]
    attribute: Annotated[str, Field(min_length=1, max_length=96)]
    operator: Annotated[str, Field(min_length=1, max_length=64)]
    expected_value: Any
    profile_scope: tuple[ProfileId, ...]
    hard: bool
    negotiable: bool
    source_hash: HashHex
    human_explanation: Annotated[str, Field(min_length=1, max_length=1200)]

    @field_validator("profile_scope", mode="before")
    @classmethod
    def _coerce_scope(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("profile_scope must be a sequence")
        items = tuple(str(item) for item in value)
        if len(items) != len(set(items)):
            raise ValueError("duplicate profile IDs in profile_scope")
        return tuple(sorted(items, key=_profile_sort_key))

    @model_validator(mode="after")
    def _validate_hard(self) -> NamedConstraint:
        if not self.hard:
            raise ValueError("Stage 6 conflict constraints must be hard constraints")
        return self

    def canonical_payload(self) -> object:
        return to_json_compatible(self)

    def constraint_hash(self) -> str:
        return domain_separated_sha256(CONSTRAINT_HASH_DOMAIN, self)


class MinimalConflictCertificate(BaseModel):
    """Subset-minimal conflict certificate for a fail-closed negotiation abort."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    certificate_version: Literal["1.0"] = "1.0"
    certificate_id: HashHex
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    initiator_agent_id: str
    responder_agent_id: str
    scenario_hash: HashHex
    task_hash: HashHex
    catalog_hash: HashHex
    initiator_manifest_hash: HashHex
    responder_manifest_hash: HashHex
    initiator_policy_compilation_hash: HashHex
    responder_policy_compilation_hash: HashHex
    commit_reveal_transcript_hash: HashHex
    candidate_profile_universe: tuple[ProfileId, ...]
    initiator_local_safe_set: tuple[ProfileId, ...]
    responder_local_safe_set: tuple[ProfileId, ...]
    common_safe_set: tuple[ProfileId, ...]
    feasibility_status: FeasibilityStatus
    conflict_category: ConflictCategory
    conflict_constraints: tuple[NamedConstraint, ...]
    original_constraint_count: Annotated[int, Field(ge=0)]
    Z3_unsat_core_size: Annotated[int, Field(ge=0)]
    IUS_size: Annotated[int, Field(ge=0)]
    shrinking_algorithm: Literal["deletion-ius-v1"] = SHRINKING_ALGORITHM_VERSION
    solver_call_count: Annotated[int, Field(gt=0)]
    issued_at: datetime
    verification_hash: HashHex

    @field_validator(
        "candidate_profile_universe",
        "initiator_local_safe_set",
        "responder_local_safe_set",
        "common_safe_set",
        mode="before",
    )
    @classmethod
    def _coerce_profiles(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("profile fields must be sequences")
        items = tuple(str(item) for item in value)
        if len(items) != len(set(items)):
            raise ValueError("duplicate profile IDs")
        return tuple(sorted(items, key=_profile_sort_key))

    @field_validator("conflict_constraints", mode="before")
    @classmethod
    def _coerce_constraints(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("conflict_constraints must be a sequence")
        return tuple(value)

    @field_validator("issued_at", mode="after")
    @classmethod
    def _normalize_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_sizes(self) -> MinimalConflictCertificate:
        ids = tuple(item.constraint_id for item in self.conflict_constraints)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate conflict constraint")
        if ids != tuple(sorted(ids)):
            raise ValueError("conflict constraints must be sorted by constraint_id")
        if self.IUS_size != len(self.conflict_constraints):
            raise ValueError("IUS_size must equal conflict constraint count")
        if self.feasibility_status is not FeasibilityStatus.HARD_POLICY_CONFLICT:
            raise ValueError("only genuine hard-constraint infeasibility may be certified")
        return self

    def hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="python")
        payload.pop("verification_hash", None)
        return payload

    def compute_verification_hash(self) -> str:
        return domain_separated_sha256(CERTIFICATE_HASH_DOMAIN, self.hash_payload())


def stable_constraint_id(
    *,
    source_agent_id: str,
    source_type: ConstraintSourceType,
    category: str,
    attribute: str,
    operator: str,
    expected_value: object,
    profile_scope: tuple[str, ...],
    source_hash: str,
) -> str:
    normalized_scope = tuple(sorted(profile_scope, key=_profile_sort_key))
    payload = {
        "source_agent_id": source_agent_id,
        "source_type": source_type.value,
        "category": category,
        "attribute": attribute,
        "operator": operator,
        "expected_value": _canonical_expected_value(expected_value),
        "profile_scope": normalized_scope,
        "source_hash": source_hash,
    }
    return domain_separated_sha256(CONSTRAINT_HASH_DOMAIN, payload)


def certificate_id_for(session_id: str, constraint_ids: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(CERTIFICATE_ID_DOMAIN)
    digest.update(bytes.fromhex(session_id))
    for constraint_id in constraint_ids:
        digest.update(bytes.fromhex(constraint_id))
    return digest.hexdigest()


def _profile_sort_key(profile_id: str) -> tuple[int, str]:
    suffix = profile_id[1:]
    return (int(suffix), profile_id) if suffix.isdigit() else (10**9, profile_id)


def _canonical_expected_value(value: object) -> object:
    if isinstance(value, list | tuple | set | frozenset) and all(
        isinstance(item, str) and item.startswith("P") for item in value
    ):
        return tuple(sorted((str(item) for item in value), key=_profile_sort_key))
    return value
