"""Validation helpers for policy-stage compilation."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import product

from pqtrust_agent.exceptions import PolicyCompilationError
from pqtrust_agent.models.catalog import ProfileCatalog
from pqtrust_agent.models.common import (
    CONFIDENTIALITY_HORIZON_RANK,
    OPERATIONAL_IMPACT_RANK,
    TASK_SENSITIVITY_RANK,
    ConfidentialityHorizon,
    NetworkClass,
    OperationalImpact,
    TaskSensitivity,
)
from pqtrust_agent.models.manifest import CapabilityManifestPayload
from pqtrust_agent.models.policy import AgentPolicy
from pqtrust_agent.models.requirements import requirement_dominates
from pqtrust_agent.models.task import TaskDescriptor
from pqtrust_agent.policy.mapper import derive_requirement


def validate_compilation_inputs(
    catalog: ProfileCatalog,
    manifest: CapabilityManifestPayload,
    policy: AgentPolicy,
    evaluation_time: datetime,
) -> datetime:
    """Validate local compiler inputs and return normalized evaluation time."""

    if evaluation_time.tzinfo is None or evaluation_time.utcoffset() is None:
        raise PolicyCompilationError("evaluation_time must be timezone-aware")
    normalized = evaluation_time.astimezone(UTC)
    if catalog.catalog_version != policy.catalog_version:
        raise PolicyCompilationError("catalog and policy catalog versions differ")
    if manifest.agent_id != policy.agent_id:
        raise PolicyCompilationError("manifest and policy agent IDs differ")
    if manifest.monotonic_version <= 0:
        raise PolicyCompilationError("manifest monotonic version must be positive")
    if not (manifest.issued_at <= normalized < manifest.expires_at):
        raise PolicyCompilationError("manifest is not valid at evaluation_time")

    known_profiles = set(catalog.profile_ids())
    for source, profile_ids in (
        ("manifest", manifest.supported_profile_ids),
        ("policy allowed", policy.allowed_profile_ids),
        ("policy denied", policy.denied_profile_ids),
    ):
        unknown = set(profile_ids) - known_profiles
        if unknown:
            raise PolicyCompilationError(
                f"{source} profile IDs are unknown: {tuple(sorted(unknown))!r}"
            )
    return normalized


def validate_mapper_monotonicity(policy: AgentPolicy) -> list[str]:
    """Return monotonicity validation errors for ``policy``."""

    errors: list[str] = []
    delegation_values = tuple(range(0, 9))
    session_values = tuple(
        sorted(
            {
                1,
                86400,
                *(rule.condition.minimum_expected_session_seconds or 1 for rule in policy.rules),
                *(
                    min((rule.condition.minimum_expected_session_seconds or 1) + 1, 86400)
                    for rule in policy.rules
                ),
            }
        )
    )
    sensitivities = tuple(sorted(TaskSensitivity, key=lambda item: TASK_SENSITIVITY_RANK[item]))
    impacts = tuple(sorted(OperationalImpact, key=lambda item: OPERATIONAL_IMPACT_RANK[item]))
    horizons = tuple(
        sorted(ConfidentialityHorizon, key=lambda item: CONFIDENTIALITY_HORIZON_RANK[item])
    )
    for network_class, org_class in product(
        NetworkClass,
        sorted(
            {
                "default",
                *(
                    org
                    for rule in policy.rules
                    for org in (rule.condition.organization_policy_classes or ())
                ),
            }
        ),
    ):
        for sensitivity, impact, horizon, delegation, seconds in product(
            sensitivities,
            impacts,
            horizons,
            delegation_values,
            session_values,
        ):
            low = TaskDescriptor(
                sensitivity=sensitivity,
                operational_impact=impact,
                confidentiality_horizon=horizon,
                delegation_depth=delegation,
                expected_session_seconds=seconds,
                network_class=network_class,
                organization_policy_class=org_class,
            )
            low_requirement = derive_requirement(policy, low).final_requirement
            neighbors: list[TaskDescriptor] = []
            sensitivity_index = sensitivities.index(sensitivity)
            impact_index = impacts.index(impact)
            horizon_index = horizons.index(horizon)
            session_index = session_values.index(seconds)
            if sensitivity_index + 1 < len(sensitivities):
                neighbors.append(
                    low.model_copy(
                        update={"sensitivity": sensitivities[sensitivity_index + 1]}
                    )
                )
            if impact_index + 1 < len(impacts):
                neighbors.append(
                    low.model_copy(update={"operational_impact": impacts[impact_index + 1]})
                )
            if horizon_index + 1 < len(horizons):
                neighbors.append(
                    low.model_copy(
                        update={"confidentiality_horizon": horizons[horizon_index + 1]}
                    )
                )
            if delegation < 8:
                neighbors.append(low.model_copy(update={"delegation_depth": delegation + 1}))
            if session_index + 1 < len(session_values):
                neighbors.append(
                    low.model_copy(
                        update={"expected_session_seconds": session_values[session_index + 1]}
                    )
                )
            for high in neighbors:
                high_requirement = derive_requirement(policy, high).final_requirement
                if not requirement_dominates(high_requirement, low_requirement):
                    errors.append(f"{policy.policy_id}: high task does not dominate low task")
                    return errors
    return errors
