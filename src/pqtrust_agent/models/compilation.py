"""Policy compilation result models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.profile import PROFILE_ID_RE
from pqtrust_agent.models.requirements import AssuranceRequirement

REQUIREMENT_DERIVATION_HASH_DOMAIN = "PQTrust.RequirementDerivation.v1"
POLICY_COMPILATION_HASH_DOMAIN = "PQTrust.PolicyCompilation.v1"
COMPILER_IMPLEMENTATION_VERSION: Literal["0.2.0"] = "0.2.0"


class RejectionCategory(StrEnum):
    """Stable public categories for rejected profile candidates."""

    CAPABILITY = "capability"
    ORGANIZATION_POLICY = "organization_policy"
    KEM_ASSURANCE = "kem_assurance"
    ENDPOINT_AUTHENTICATION = "endpoint_authentication"
    CONTRACT_EVIDENCE = "contract_evidence"
    FALLBACK = "fallback"
    RESUMPTION = "resumption"
    LEASE = "lease"
    RESOURCE_BOUND = "resource_bound"


REJECTION_CATEGORY_ORDER: dict[RejectionCategory, int] = {
    RejectionCategory.CAPABILITY: 0,
    RejectionCategory.ORGANIZATION_POLICY: 1,
    RejectionCategory.KEM_ASSURANCE: 2,
    RejectionCategory.ENDPOINT_AUTHENTICATION: 3,
    RejectionCategory.CONTRACT_EVIDENCE: 4,
    RejectionCategory.FALLBACK: 5,
    RejectionCategory.RESUMPTION: 6,
    RejectionCategory.LEASE: 7,
    RejectionCategory.RESOURCE_BOUND: 8,
}

ProfileId = Annotated[str, Field(pattern=PROFILE_ID_RE)]


def sort_rejection_categories(
    categories: tuple[RejectionCategory, ...] | list[RejectionCategory] | set[RejectionCategory],
) -> tuple[RejectionCategory, ...]:
    """Return categories in canonical public order."""

    return tuple(sorted(set(categories), key=lambda item: REJECTION_CATEGORY_ORDER[item]))


class RequirementDerivation(BaseModel):
    """Deterministic derivation record for task-specific assurance requirements."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    policy_id: str
    policy_version: Annotated[int, Field(gt=0, strict=True)]
    policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    task_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    base_requirement: AssuranceRequirement
    matched_rule_ids: tuple[str, ...]
    final_requirement: AssuranceRequirement
    derivation_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("matched_rule_ids", mode="before")
    @classmethod
    def _coerce_rule_ids(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("matched_rule_ids must be a sequence")
        return tuple(str(item) for item in value)

    @staticmethod
    def compute_hash_payload(
        *,
        agent_id: str,
        policy_id: str,
        policy_version: int,
        policy_hash: str,
        task_hash: str,
        base_requirement: AssuranceRequirement,
        matched_rule_ids: tuple[str, ...],
        final_requirement: AssuranceRequirement,
    ) -> dict[str, object]:
        """Return the payload used for the derivation hash."""

        return {
            "agent_id": agent_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "task_hash": task_hash,
            "base_requirement": base_requirement,
            "matched_rule_ids": matched_rule_ids,
            "final_requirement": final_requirement,
        }

    def canonical_payload(self) -> object:
        """Return the JSON-compatible derivation payload."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes."""

        return canonicalize(self)


class ProfileCompilationDecision(BaseModel):
    """Compilation outcome for one profile candidate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    profile_id: ProfileId
    accepted: bool
    violated_categories: tuple[RejectionCategory, ...]
    irreducible_unsat_core: tuple[RejectionCategory, ...]
    solver_status: Literal["sat", "unsat"]

    @field_validator("violated_categories", "irreducible_unsat_core", mode="before")
    @classmethod
    def _coerce_categories(cls, value: object) -> tuple[RejectionCategory, ...]:
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("categories must be a sequence")
        return sort_rejection_categories(tuple(RejectionCategory(item) for item in value))

    @model_validator(mode="after")
    def _validate_explanations(self) -> ProfileCompilationDecision:
        if self.accepted:
            if self.violated_categories or self.irreducible_unsat_core:
                raise ValueError("accepted profiles must not carry rejection explanations")
            if self.solver_status != "sat":
                raise ValueError("accepted profiles must have sat solver status")
        elif self.solver_status != "unsat":
            raise ValueError("rejected profiles must have unsat solver status")
        return self


class PolicyCompilationResult(BaseModel):
    """Deterministic local safe-set compilation result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    compiler_schema_version: Literal["1.0"] = "1.0"
    compiler_implementation_version: Literal["0.2.0"] = COMPILER_IMPLEMENTATION_VERSION
    z3_version: str
    agent_id: str
    policy_id: str
    policy_version: Annotated[int, Field(gt=0, strict=True)]
    policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    manifest_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    task_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    catalog_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    evaluation_time: datetime
    requirement_derivation: RequirementDerivation
    safe_profile_ids: tuple[ProfileId, ...]
    profile_decisions: tuple[ProfileCompilationDecision, ...]
    solver_timeout_ms: Annotated[int, Field(gt=0, le=60000, strict=True)]
    compilation_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("evaluation_time", mode="after")
    @classmethod
    def _normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation_time must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("safe_profile_ids", mode="before")
    @classmethod
    def _coerce_safe_ids(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("safe_profile_ids must be a sequence")
        return tuple(str(item) for item in value)

    @field_validator("profile_decisions", mode="before")
    @classmethod
    def _coerce_decisions(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("profile_decisions must be a sequence")
        return tuple(value)

    @staticmethod
    def compute_hash_payload(
        *,
        compiler_schema_version: str,
        compiler_implementation_version: str,
        z3_version: str,
        agent_id: str,
        policy_id: str,
        policy_version: int,
        policy_hash: str,
        manifest_hash: str,
        task_hash: str,
        catalog_hash: str,
        evaluation_time: datetime,
        requirement_derivation: RequirementDerivation,
        safe_profile_ids: tuple[str, ...],
        profile_decisions: tuple[ProfileCompilationDecision, ...],
        solver_timeout_ms: int,
    ) -> dict[str, object]:
        """Return the payload used for the compilation hash."""

        return {
            "compiler_schema_version": compiler_schema_version,
            "compiler_implementation_version": compiler_implementation_version,
            "z3_version": z3_version,
            "agent_id": agent_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "manifest_hash": manifest_hash,
            "task_hash": task_hash,
            "catalog_hash": catalog_hash,
            "evaluation_time": evaluation_time,
            "requirement_derivation": requirement_derivation,
            "safe_profile_ids": safe_profile_ids,
            "profile_decisions": profile_decisions,
            "solver_timeout_ms": solver_timeout_ms,
        }

    def canonical_payload(self) -> object:
        """Return the JSON-compatible compilation payload."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes."""

        return canonicalize(self)


def derivation_hash(payload: dict[str, object]) -> str:
    """Return the domain-separated derivation hash."""

    return domain_separated_sha256(REQUIREMENT_DERIVATION_HASH_DOMAIN, payload)


def compilation_hash(payload: dict[str, object]) -> str:
    """Return the domain-separated compilation hash."""

    return domain_separated_sha256(POLICY_COMPILATION_HASH_DOMAIN, payload)
