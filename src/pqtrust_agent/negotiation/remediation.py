"""Non-binding remediation reports for conflict certificates."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from pqtrust_agent.models.conflict import MinimalConflictCertificate
from pqtrust_agent.negotiation.conflict_constraints import satisfiable_profile_ids

NON_RELAXABLE_CATEGORIES = {
    "minimum_assurance",
    "endpoint_authentication",
    "explicit_profile_denial",
    "fallback_policy",
}


class EvaluatedRelaxation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    constraint_id: str
    agent_id: str
    negotiable: bool
    feasible_if_removed: bool
    newly_feasible_profiles: tuple[str, ...]
    security_consequence: str
    configuration_change_required_by: str


class RemediationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    certificate_id: str
    evaluated_relaxations: tuple[EvaluatedRelaxation, ...]
    individually_sufficient_relaxations: tuple[str, ...]
    no_safe_remediation_available: bool
    informational_only: bool = Field(default=True)
    automatically_applied: bool = Field(default=False)


def build_remediation_report(certificate: MinimalConflictCertificate) -> RemediationReport:
    evaluations: list[EvaluatedRelaxation] = []
    sufficient: list[str] = []
    for constraint in certificate.conflict_constraints:
        allowed_to_test = (
            constraint.negotiable and constraint.category not in NON_RELAXABLE_CATEGORIES
        )
        profiles: tuple[str, ...] = ()
        if allowed_to_test:
            remainder = tuple(
                item
                for item in certificate.conflict_constraints
                if item.constraint_id != constraint.constraint_id
            )
            profiles = satisfiable_profile_ids(
                profile_ids=certificate.candidate_profile_universe,
                constraints=remainder,
            )
            if profiles:
                sufficient.append(constraint.constraint_id)
        evaluations.append(
            EvaluatedRelaxation(
                constraint_id=constraint.constraint_id,
                agent_id=constraint.source_agent_id,
                negotiable=constraint.negotiable,
                feasible_if_removed=bool(profiles),
                newly_feasible_profiles=profiles,
                security_consequence=(
                    "No relaxation tested for this hard non-negotiable security constraint."
                    if not allowed_to_test
                    else f"Would remove hard {constraint.category} for this session only."
                ),
                configuration_change_required_by=constraint.source_agent_id,
            )
        )
    return RemediationReport(
        certificate_id=certificate.certificate_id,
        evaluated_relaxations=tuple(evaluations),
        individually_sufficient_relaxations=tuple(sufficient),
        no_safe_remediation_available=not sufficient,
    )
