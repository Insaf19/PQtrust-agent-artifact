"""Finite-domain Z3 encoding for local policy compilation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import z3

from pqtrust_agent.assurance.order import dominates
from pqtrust_agent.models.catalog import ProfileCatalog
from pqtrust_agent.models.common import (
    FALLBACK_RULE_RANK,
    LEASE_STRICTNESS_RANK,
    RESUMPTION_RULE_RANK,
)
from pqtrust_agent.models.compilation import RejectionCategory, sort_rejection_categories
from pqtrust_agent.models.manifest import CapabilityManifestPayload
from pqtrust_agent.models.policy import AgentPolicy
from pqtrust_agent.models.profile import TrustProfile
from pqtrust_agent.models.requirements import AssuranceRequirement
from pqtrust_agent.models.task import TaskDescriptor

SELECTED_PROFILE_INDEX = "pqtrust.policy.v1.selected_profile_index"


@dataclass(frozen=True)
class ConstraintEncoding:
    """Z3 expressions and labels for one compiler invocation."""

    selected_profile_index: z3.ArithRef
    constraints: dict[RejectionCategory, z3.BoolRef]
    labels: dict[RejectionCategory, z3.BoolRef]


def _category_name(category: RejectionCategory) -> str:
    return f"pqtrust.policy.v1.assumption.{category.value}"


def _indexed_bool(
    selected_index: z3.ArithRef,
    profiles: tuple[TrustProfile, ...],
    predicate: Callable[[TrustProfile], bool],
) -> z3.BoolRef:
    return z3.Or(
        *(
            z3.And(selected_index == index, z3.BoolVal(predicate(profile)))
            for index, profile in enumerate(profiles)
        )
    )


def build_constraint_encoding(
    catalog: ProfileCatalog,
    manifest: CapabilityManifestPayload,
    policy: AgentPolicy,
    task: TaskDescriptor,
    requirement: AssuranceRequirement,
) -> ConstraintEncoding:
    """Build stable hard-constraint expressions over the finite profile catalog."""

    selected = z3.Int(SELECTED_PROFILE_INDEX)
    profiles = catalog.profiles
    allowed = set(policy.allowed_profile_ids)
    denied = set(policy.denied_profile_ids)
    supported = set(manifest.supported_profile_ids)
    constraints: dict[RejectionCategory, z3.BoolRef] = {
        RejectionCategory.CAPABILITY: z3.And(
            selected >= 0,
            selected < len(profiles),
            _indexed_bool(selected, profiles, lambda profile: profile.profile_id in supported),
        ),
        RejectionCategory.ORGANIZATION_POLICY: z3.And(
            _indexed_bool(selected, profiles, lambda profile: profile.profile_id in allowed),
            _indexed_bool(selected, profiles, lambda profile: profile.profile_id not in denied),
        ),
        RejectionCategory.KEM_ASSURANCE: _indexed_bool(
            selected,
            profiles,
            lambda profile: profile.assurance.key_establishment_threats.issuperset(
                requirement.key_establishment_threats
            ),
        ),
        RejectionCategory.ENDPOINT_AUTHENTICATION: z3.And(
            _indexed_bool(
                selected,
                profiles,
                lambda profile: profile.assurance.endpoint_authentication_threats.issuperset(
                    requirement.endpoint_authentication_threats
                ),
            ),
            _indexed_bool(
                selected,
                profiles,
                lambda profile: policy.permitted_endpoint_authentication_modes is None
                or profile.endpoint_authentication_mode
                in policy.permitted_endpoint_authentication_modes,
            ),
        ),
        RejectionCategory.CONTRACT_EVIDENCE: z3.And(
            _indexed_bool(
                selected,
                profiles,
                lambda profile: profile.assurance.contract_evidence_threats.issuperset(
                    requirement.contract_evidence_threats
                ),
            ),
            _indexed_bool(
                selected,
                profiles,
                lambda profile: policy.permitted_contract_evidence_modes is None
                or profile.contract_evidence_mode in policy.permitted_contract_evidence_modes,
            ),
        ),
        RejectionCategory.FALLBACK: _indexed_bool(
            selected,
            profiles,
            lambda profile: FALLBACK_RULE_RANK[profile.fallback_rule]
            >= FALLBACK_RULE_RANK[requirement.fallback_rule],
        ),
        RejectionCategory.RESUMPTION: _indexed_bool(
            selected,
            profiles,
            lambda profile: RESUMPTION_RULE_RANK[profile.resumption_rule]
            >= RESUMPTION_RULE_RANK[requirement.resumption_rule],
        ),
        RejectionCategory.LEASE: z3.And(
            _indexed_bool(
                selected,
                profiles,
                lambda profile: LEASE_STRICTNESS_RANK[profile.lease_strictness]
                >= LEASE_STRICTNESS_RANK[requirement.lease_strictness],
            ),
            _indexed_bool(
                selected,
                profiles,
                lambda profile: task.expected_session_seconds <= profile.max_lease_seconds,
            ),
        ),
    }
    labels = {category: z3.Bool(_category_name(category)) for category in constraints}
    return ConstraintEncoding(selected, constraints, labels)


def profile_violated_categories(
    profile: TrustProfile,
    manifest: CapabilityManifestPayload,
    policy: AgentPolicy,
    task: TaskDescriptor,
    requirement: AssuranceRequirement,
) -> tuple[RejectionCategory, ...]:
    """Return every hard-constraint category violated by ``profile``."""

    categories: list[RejectionCategory] = []
    if profile.profile_id not in manifest.supported_profile_ids:
        categories.append(RejectionCategory.CAPABILITY)
    if (
        profile.profile_id not in policy.allowed_profile_ids
        or profile.profile_id in policy.denied_profile_ids
    ):
        categories.append(RejectionCategory.ORGANIZATION_POLICY)
    if not profile.assurance.key_establishment_threats.issuperset(
        requirement.key_establishment_threats
    ):
        categories.append(RejectionCategory.KEM_ASSURANCE)
    if not profile.assurance.endpoint_authentication_threats.issuperset(
        requirement.endpoint_authentication_threats
    ) or (
        policy.permitted_endpoint_authentication_modes is not None
        and profile.endpoint_authentication_mode
        not in policy.permitted_endpoint_authentication_modes
    ):
        categories.append(RejectionCategory.ENDPOINT_AUTHENTICATION)
    if not profile.assurance.contract_evidence_threats.issuperset(
        requirement.contract_evidence_threats
    ) or (
        policy.permitted_contract_evidence_modes is not None
        and profile.contract_evidence_mode not in policy.permitted_contract_evidence_modes
    ):
        categories.append(RejectionCategory.CONTRACT_EVIDENCE)
    if FALLBACK_RULE_RANK[profile.fallback_rule] < FALLBACK_RULE_RANK[requirement.fallback_rule]:
        categories.append(RejectionCategory.FALLBACK)
    if RESUMPTION_RULE_RANK[profile.resumption_rule] < RESUMPTION_RULE_RANK[
        requirement.resumption_rule
    ]:
        categories.append(RejectionCategory.RESUMPTION)
    if (
        LEASE_STRICTNESS_RANK[profile.lease_strictness]
        < LEASE_STRICTNESS_RANK[requirement.lease_strictness]
        or task.expected_session_seconds > profile.max_lease_seconds
    ):
        categories.append(RejectionCategory.LEASE)
    if not dominates(profile.assurance, requirement.as_assurance_vector()):
        # Defensive check only; all assurance dimensions above are public categories.
        pass
    return sort_rejection_categories(categories)
