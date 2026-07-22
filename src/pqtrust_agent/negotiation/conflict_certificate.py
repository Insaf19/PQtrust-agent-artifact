"""Minimal conflict certificate construction and taxonomy."""

from __future__ import annotations

from datetime import datetime

from pqtrust_agent.models.conflict import (
    ConflictCategory,
    FeasibilityStatus,
    MinimalConflictCertificate,
    NamedConstraint,
    certificate_id_for,
)
from pqtrust_agent.negotiation.unsat_core import IUSResult, compute_ius

CATEGORY_MAP: dict[str, ConflictCategory] = {
    "profile_support": ConflictCategory.NO_COMMON_PROFILE,
    "minimum_assurance": ConflictCategory.ASSURANCE_FLOOR_CONFLICT,
    "endpoint_authentication": ConflictCategory.ENDPOINT_AUTHENTICATION_CONFLICT,
    "TLS_group_support": ConflictCategory.TLS_GROUP_CONFLICT,
    "contract_evidence_algorithm": ConflictCategory.CONTRACT_EVIDENCE_CONFLICT,
    "fallback_policy": ConflictCategory.FALLBACK_POLICY_CONFLICT,
    "resumption_policy": ConflictCategory.RESUMPTION_POLICY_CONFLICT,
    "lease_limit": ConflictCategory.LEASE_CONFLICT,
    "handshake_byte_limit": ConflictCategory.RESOURCE_LIMIT_CONFLICT,
    "explicit_profile_denial": ConflictCategory.CAPABILITY_MISMATCH,
}


def classify_conflict(ius: tuple[NamedConstraint, ...]) -> ConflictCategory:
    categories = {
        category
        for constraint in ius
        if (category := CATEGORY_MAP.get(constraint.category)) is not None
    }
    if len(categories) == 1:
        return next(iter(categories))
    return ConflictCategory.MULTI_CAUSE_CONFLICT


def common_safe_set(
    profile_ids: tuple[str, ...],
    initiator_safe_set: tuple[str, ...],
    responder_safe_set: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        profile_id
        for profile_id in profile_ids
        if profile_id in initiator_safe_set and profile_id in responder_safe_set
    )


def build_minimal_conflict_certificate(
    *,
    session_id: str,
    initiator_agent_id: str,
    responder_agent_id: str,
    scenario_hash: str,
    task_hash: str,
    catalog_hash: str,
    initiator_manifest_hash: str,
    responder_manifest_hash: str,
    initiator_policy_compilation_hash: str,
    responder_policy_compilation_hash: str,
    commit_reveal_transcript_hash: str,
    candidate_profile_universe: tuple[str, ...],
    initiator_local_safe_set: tuple[str, ...],
    responder_local_safe_set: tuple[str, ...],
    constraints: tuple[NamedConstraint, ...],
    issued_at: datetime,
) -> tuple[MinimalConflictCertificate, IUSResult]:
    ius_result = compute_ius(profile_ids=candidate_profile_universe, constraints=constraints)
    ius = ius_result.ius
    certificate_id = certificate_id_for(
        session_id,
        tuple(constraint.constraint_id for constraint in ius),
    )
    certificate = MinimalConflictCertificate(
        certificate_id=certificate_id,
        session_id=session_id,
        initiator_agent_id=initiator_agent_id,
        responder_agent_id=responder_agent_id,
        scenario_hash=scenario_hash,
        task_hash=task_hash,
        catalog_hash=catalog_hash,
        initiator_manifest_hash=initiator_manifest_hash,
        responder_manifest_hash=responder_manifest_hash,
        initiator_policy_compilation_hash=initiator_policy_compilation_hash,
        responder_policy_compilation_hash=responder_policy_compilation_hash,
        commit_reveal_transcript_hash=commit_reveal_transcript_hash,
        candidate_profile_universe=candidate_profile_universe,
        initiator_local_safe_set=initiator_local_safe_set,
        responder_local_safe_set=responder_local_safe_set,
        common_safe_set=common_safe_set(
            candidate_profile_universe,
            initiator_local_safe_set,
            responder_local_safe_set,
        ),
        feasibility_status=FeasibilityStatus.HARD_POLICY_CONFLICT,
        conflict_category=classify_conflict(ius),
        conflict_constraints=ius,
        original_constraint_count=ius_result.original_constraint_count,
        Z3_unsat_core_size=ius_result.Z3_unsat_core_size,
        IUS_size=ius_result.IUS_size,
        solver_call_count=ius_result.solver_call_count,
        issued_at=issued_at,
        verification_hash="0" * 64,
    )
    certificate = certificate.model_copy(
        update={"verification_hash": certificate.compute_verification_hash()}
    )
    return certificate, ius_result
