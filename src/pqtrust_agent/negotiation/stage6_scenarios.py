"""Registered Stage 6 infeasible scenario constructors."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pqtrust_agent.models.conflict import ConstraintSourceType
from pqtrust_agent.negotiation.conflict_constraints import make_named_constraint

SCENARIO_ID_UNKNOWN = "SCENARIO_ID_UNKNOWN"
SCENARIO_SOURCE_NOT_FOUND = "SCENARIO_SOURCE_NOT_FOUND"
SCENARIO_ID_MISMATCH = "SCENARIO_ID_MISMATCH"

NOW = datetime(2026, 7, 14, 0, 0, tzinfo=UTC)
PROFILES = ("P0", "P1", "P2", "P3", "P4")
INFEASIBLE_SCENARIO_IDS = (
    "no-common-profile",
    "assurance-floor-conflict",
    "TLS-group-capability-conflict",
    "lease-policy-conflict",
    "multi-cause-conflict",
)


class ScenarioRegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class Stage6ConflictScenario:
    scenario_id: str
    initiator_safe: tuple[str, ...]
    responder_safe: tuple[str, ...]
    extra_constraints: tuple[Any, ...]
    capability_intersection_before_policy: tuple[str, ...] = PROFILES
    candidate_set_after_assurance_floor: tuple[str, ...] = PROFILES
    task_minimum_lease_seconds: int | None = None
    agent_profile_maximum_lease_seconds: int | None = None
    otherwise_compatible_candidate_profiles: tuple[str, ...] = PROFILES

    @property
    def name(self) -> str:
        return self.scenario_id


def scenario_hash(scenario_id: str) -> str:
    return _hash(scenario_id)


def task_hash(scenario_id: str) -> str:
    return _hash(f"{scenario_id}-task")


def session_id(scenario_id: str) -> str:
    return _hash(f"session-{scenario_id}")


def stable_hash(value: str) -> str:
    return _hash(value)


def constraints_for_scenario(scenario: Stage6ConflictScenario) -> tuple[Any, ...]:
    name = scenario.scenario_id
    init_safe = scenario.initiator_safe
    resp_safe = scenario.responder_safe
    return (
        make_named_constraint(
            source_agent_id="initiator",
            source_type=ConstraintSourceType.PRIVATE_POLICY,
            category="profile_support",
            attribute="selected_profile_id",
            operator="in",
            expected_value=init_safe,
            profile_scope=init_safe,
            source_hash=_hash(f"{name}-init-policy"),
            human_explanation="Initiator hard policy permits this safe set only.",
        ),
        make_named_constraint(
            source_agent_id="responder",
            source_type=ConstraintSourceType.PRIVATE_POLICY,
            category="profile_support",
            attribute="selected_profile_id",
            operator="in",
            expected_value=resp_safe,
            profile_scope=resp_safe,
            source_hash=_hash(f"{name}-resp-policy"),
            human_explanation="Responder hard policy permits this safe set only.",
        ),
        *scenario.extra_constraints,
    )


def registered_infeasible_scenarios() -> tuple[Stage6ConflictScenario, ...]:
    return (
        Stage6ConflictScenario("no-common-profile", ("P0", "P1"), ("P4",), ()),
        Stage6ConflictScenario(
            "assurance-floor-conflict",
            PROFILES,
            PROFILES,
            (
                make_named_constraint(
                    source_agent_id="task",
                    source_type=ConstraintSourceType.TASK,
                    category="minimum_assurance",
                    attribute="assurance_floor",
                    operator=">=",
                    expected_value={"minimum_level": "high", "profiles": ("P3", "P4")},
                    profile_scope=("P3", "P4"),
                    source_hash=_hash("assurance-task-floor"),
                    human_explanation=(
                        "The task assurance floor admits only high-assurance profiles."
                    ),
                ),
                make_named_constraint(
                    source_agent_id="responder",
                    source_type=ConstraintSourceType.MANIFEST,
                    category="minimum_assurance",
                    attribute="assurance_capability",
                    operator="in",
                    expected_value={"maximum_level": "medium", "profiles": ("P0", "P1", "P2")},
                    profile_scope=("P0", "P1", "P2"),
                    source_hash=_hash("assurance-responder-capability"),
                    human_explanation="Responder assurance evidence supports only lower profiles.",
                ),
            ),
            capability_intersection_before_policy=PROFILES,
            candidate_set_after_assurance_floor=("P3", "P4"),
        ),
        Stage6ConflictScenario(
            "TLS-group-capability-conflict",
            PROFILES,
            PROFILES,
            (
                make_named_constraint(
                    source_agent_id="initiator",
                    source_type=ConstraintSourceType.MANIFEST,
                    category="TLS_group_support",
                    attribute="tls_group",
                    operator="in",
                    expected_value=("P0", "P1"),
                    profile_scope=("P0", "P1"),
                    source_hash=_hash("tls-init"),
                    human_explanation="Initiator TLS support is limited to P0 and P1.",
                ),
                make_named_constraint(
                    source_agent_id="responder",
                    source_type=ConstraintSourceType.MANIFEST,
                    category="TLS_group_support",
                    attribute="tls_group",
                    operator="in",
                    expected_value=("P3", "P4"),
                    profile_scope=("P3", "P4"),
                    source_hash=_hash("tls-resp"),
                    human_explanation="Responder TLS support is limited to P3 and P4.",
                ),
            ),
        ),
        Stage6ConflictScenario(
            "lease-policy-conflict",
            PROFILES,
            PROFILES,
            (
                make_named_constraint(
                    source_agent_id="task",
                    source_type=ConstraintSourceType.TASK,
                    category="lease_limit",
                    attribute="expected_session_seconds",
                    operator="<=",
                    expected_value={"minimum_lease_seconds": 900, "profiles": ("P3", "P4")},
                    profile_scope=("P3", "P4"),
                    source_hash=_hash("lease-task"),
                    human_explanation="Task lease floor can be met only by the disclosed profiles.",
                ),
                make_named_constraint(
                    source_agent_id="responder",
                    source_type=ConstraintSourceType.PRIVATE_POLICY,
                    category="lease_limit",
                    attribute="maximum_lease_seconds",
                    operator="in",
                    expected_value={"maximum_lease_seconds": 300, "profiles": ("P0", "P1", "P2")},
                    profile_scope=("P0", "P1", "P2"),
                    source_hash=_hash("lease-policy"),
                    human_explanation="Responder lease ceiling permits only disclosed profiles.",
                ),
            ),
            task_minimum_lease_seconds=900,
            agent_profile_maximum_lease_seconds=300,
            otherwise_compatible_candidate_profiles=PROFILES,
        ),
        Stage6ConflictScenario(
            "multi-cause-conflict",
            PROFILES,
            PROFILES,
            (
                make_named_constraint(
                    source_agent_id="initiator",
                    source_type=ConstraintSourceType.MANIFEST,
                    category="TLS_group_support",
                    attribute="tls_group",
                    operator="in",
                    expected_value=("P0", "P1"),
                    profile_scope=("P0", "P1"),
                    source_hash=_hash("multi-tls"),
                    human_explanation="Initiator TLS support permits only the disclosed profiles.",
                ),
                make_named_constraint(
                    source_agent_id="task",
                    source_type=ConstraintSourceType.TASK,
                    category="lease_limit",
                    attribute="expected_session_seconds",
                    operator="<=",
                    expected_value=("P3", "P4"),
                    profile_scope=("P3", "P4"),
                    source_hash=_hash("multi-lease"),
                    human_explanation="Task lease requirement permits only the disclosed profiles.",
                ),
            ),
        ),
    )


def resolve_infeasible_scenario(repo: Path, scenario_id: str) -> Stage6ConflictScenario:
    del repo
    registry: dict[str, Stage6ConflictScenario] = {}
    for scenario in registered_infeasible_scenarios():
        if scenario.scenario_id in registry:
            raise ScenarioRegistryError(
                SCENARIO_ID_MISMATCH,
                f"duplicate registered infeasible scenario ID {scenario.scenario_id!r}",
            )
        registry[scenario.scenario_id] = scenario
    if scenario_id not in registry:
        raise ScenarioRegistryError(
            SCENARIO_ID_UNKNOWN,
            f"unknown infeasible scenario ID {scenario_id!r}",
        )
    scenario = registry[scenario_id]
    if scenario.scenario_id != scenario_id:
        raise ScenarioRegistryError(
            SCENARIO_ID_MISMATCH,
            f"resolved scenario ID {scenario.scenario_id!r} did not match {scenario_id!r}",
        )
    return scenario


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
