from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import z3
from pydantic import ValidationError

from pqtrust_agent.exceptions import PolicyCompilationError, PolicyValidationError
from pqtrust_agent.models import (
    CONFIDENTIALITY_HORIZON_RANK,
    OPERATIONAL_IMPACT_RANK,
    TASK_SENSITIVITY_RANK,
    AgentPolicy,
    AssuranceRequirement,
    FallbackRule,
    LeaseStrictness,
    OperationalImpact,
    PolicyRule,
    RejectionCategory,
    RequirementContribution,
    ResumptionRule,
    TaskRuleCondition,
    TaskSensitivity,
    ThreatClass,
    requirement_dominates,
)
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario
from pqtrust_agent.policy.mapper import derive_requirement
from pqtrust_agent.policy.z3_encoding import build_constraint_encoding

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG = load_profile_catalog(REPO_ROOT / "configs/profiles/trust_profiles.yaml")
AGENTS = REPO_ROOT / "configs/agents"
POLICIES = REPO_ROOT / "configs/policies"
SCENARIOS = REPO_ROOT / "configs/scenarios"


def _base_requirement() -> AssuranceRequirement:
    return AssuranceRequirement(
        key_establishment_threats=frozenset({ThreatClass.CLASSICAL}),
        endpoint_authentication_threats=frozenset({ThreatClass.CLASSICAL}),
        contract_evidence_threats=frozenset({ThreatClass.CLASSICAL, ThreatClass.QUANTUM}),
        fallback_rule=FallbackRule.LOW_RISK_ONLY,
        resumption_rule=ResumptionRule.CONTEXT_BOUND,
        lease_strictness=LeaseStrictness.LONG,
    )


def _load_result(scenario_name: str, agent_id: str) -> object:
    scenario = load_scenario(SCENARIOS / f"{scenario_name}.yaml")
    manifest = load_agent_manifest(AGENTS / f"{agent_id.replace('-', '_')}.yaml")
    policy = load_agent_policy(POLICIES / f"{agent_id.replace('-', '_')}.yaml")
    return compile_local_policy(
        CATALOG,
        manifest,
        policy,
        scenario.task,
        scenario.evaluation_time_utc,
    )


def _core_status(
    scenario_name: str,
    agent_id: str,
    profile_id: str,
    categories: tuple[RejectionCategory, ...],
) -> object:
    scenario = load_scenario(SCENARIOS / f"{scenario_name}.yaml")
    manifest = load_agent_manifest(AGENTS / f"{agent_id.replace('-', '_')}.yaml")
    policy = load_agent_policy(POLICIES / f"{agent_id.replace('-', '_')}.yaml")
    derivation = derive_requirement(policy, scenario.task)
    encoding = build_constraint_encoding(
        CATALOG,
        manifest,
        policy,
        scenario.task,
        derivation.final_requirement,
    )
    solver = z3.Solver()
    solver.set(timeout=policy.solver_timeout_ms)
    for category, constraint in encoding.constraints.items():
        solver.add(z3.Implies(encoding.labels[category], constraint))
    solver.add(encoding.selected_profile_index == CATALOG.profile_ids().index(profile_id))
    return solver.check(*(encoding.labels[category] for category in categories))


def test_explicit_task_rank_mappings() -> None:
    assert TASK_SENSITIVITY_RANK[TaskSensitivity.PUBLIC] < TASK_SENSITIVITY_RANK[
        TaskSensitivity.INTERNAL
    ]
    assert TASK_SENSITIVITY_RANK[TaskSensitivity.CONFIDENTIAL] < TASK_SENSITIVITY_RANK[
        TaskSensitivity.RESTRICTED
    ]
    assert OPERATIONAL_IMPACT_RANK[OperationalImpact.OBSERVATION] < OPERATIONAL_IMPACT_RANK[
        OperationalImpact.PHYSICAL_CONTROL
    ]
    assert CONFIDENTIALITY_HORIZON_RANK


def test_rule_lower_bound_matching_and_sorted_derivation() -> None:
    policy = load_agent_policy(POLICIES / "cloud_orchestrator.yaml")
    scenario = load_scenario(SCENARIOS / "critical_edge_command.yaml")

    derivation = derive_requirement(policy, scenario.task)

    assert derivation.matched_rule_ids == tuple(sorted(derivation.matched_rule_ids))
    assert "restricted-task" in derivation.matched_rule_ids
    assert derivation.final_requirement.fallback_rule is FallbackRule.FORBIDDEN


def test_contribution_join_cannot_weaken() -> None:
    base = _base_requirement().model_copy(
        update={"fallback_rule": FallbackRule.FORBIDDEN}
    )
    weakened = RequirementContribution(fallback_rule=FallbackRule.LOW_RISK_ONLY)

    assert weakened.apply_to(base).fallback_rule is FallbackRule.FORBIDDEN


def test_policy_duplicate_rules_and_allow_deny_overlap_rejected() -> None:
    rule = PolicyRule(
        rule_id="abc",
        description="duplicate",
        condition=TaskRuleCondition(),
        contribution=RequirementContribution(fallback_rule=FallbackRule.EXPLICIT_ONLY),
    )
    with pytest.raises(ValidationError):
        AgentPolicy(
            policy_id="p",
            policy_version=1,
            agent_id="a",
            catalog_version="1.0",
            base_requirement=_base_requirement(),
            allowed_profile_ids=("P0",),
            denied_profile_ids=(),
            rules=(rule, rule),
        )
    with pytest.raises(ValidationError):
        AgentPolicy(
            policy_id="p",
            policy_version=1,
            agent_id="a",
            catalog_version="1.0",
            base_requirement=_base_requirement(),
            allowed_profile_ids=("P0",),
            denied_profile_ids=("P0",),
        )


def test_compilation_input_rejections() -> None:
    scenario = load_scenario(SCENARIOS / "low_risk_public_tool.yaml")
    manifest = load_agent_manifest(AGENTS / "public_tool_agent.yaml")
    policy = load_agent_policy(POLICIES / "public_tool_agent.yaml")
    bad_policy = policy.model_copy(update={"agent_id": "other-agent"})
    expired_time = datetime(2035, 1, 1, tzinfo=UTC)

    with pytest.raises(PolicyCompilationError):
        compile_local_policy(
            CATALOG,
            manifest,
            bad_policy,
            scenario.task,
            scenario.evaluation_time_utc,
        )
    with pytest.raises(PolicyCompilationError):
        compile_local_policy(CATALOG, manifest, policy, scenario.task, expired_time)
    unknown_profile_policy = policy.model_copy(update={"allowed_profile_ids": ("P9",)})
    with pytest.raises(PolicyCompilationError):
        compile_local_policy(
            CATALOG,
            manifest,
            unknown_profile_policy,
            scenario.task,
            scenario.evaluation_time_utc,
        )


def test_hash_stability() -> None:
    policy = load_agent_policy(POLICIES / "cloud_orchestrator.yaml")
    scenario = load_scenario(SCENARIOS / "sensitive_enterprise_api.yaml")
    first = derive_requirement(policy, scenario.task)
    second = derive_requirement(policy, scenario.task)

    assert first.derivation_hash == second.derivation_hash
    reloaded_policy = load_agent_policy(POLICIES / "cloud_orchestrator.yaml")
    assert policy.policy_hash() == reloaded_policy.policy_hash()
    assert scenario.scenario_hash() == load_scenario(
        SCENARIOS / "sensitive_enterprise_api.yaml"
    ).scenario_hash()


def test_expected_configured_common_safe_sets() -> None:
    expected = {
        "low_risk_public_tool": ("P0", "P1"),
        "sensitive_enterprise_api": ("P1", "P2", "P3"),
        "critical_edge_command": ("P4",),
    }
    responders = {
        "low_risk_public_tool": "public-tool-agent",
        "sensitive_enterprise_api": "enterprise-api-agent",
        "critical_edge_command": "edge-control-agent",
    }
    for scenario_id, expected_common in expected.items():
        initiator = _load_result(scenario_id, "cloud-orchestrator")
        responder = _load_result(scenario_id, responders[scenario_id])
        common = tuple(
            profile_id
            for profile_id in CATALOG.profile_ids()
            if profile_id in initiator.safe_profile_ids and profile_id in responder.safe_profile_ids
        )
        assert common == expected_common


def test_rejection_explanations_and_category_oracles() -> None:
    sensitive = _load_result("sensitive_enterprise_api", "cloud-orchestrator")
    decisions = {decision.profile_id: decision for decision in sensitive.profile_decisions}

    assert sensitive.safe_profile_ids == ("P1", "P2", "P3")
    assert RejectionCategory.KEM_ASSURANCE in decisions["P0"].violated_categories
    assert RejectionCategory.LEASE in decisions["P4"].violated_categories
    assert all(
        RejectionCategory.RESOURCE_BOUND not in decision.violated_categories
        for decision in sensitive.profile_decisions
    )
    for decision in sensitive.profile_decisions:
        if decision.accepted:
            assert decision.violated_categories == ()
            assert decision.irreducible_unsat_core == ()
        else:
            assert decision.violated_categories
            assert decision.irreducible_unsat_core


def test_irreducible_cores_are_subset_minimal() -> None:
    result = _load_result("sensitive_enterprise_api", "cloud-orchestrator")

    for decision in result.profile_decisions:
        if decision.accepted:
            continue
        core = decision.irreducible_unsat_core
        assert _core_status(
            "sensitive_enterprise_api",
            "cloud-orchestrator",
            decision.profile_id,
            core,
        ) == z3.unsat
        for category in core:
            reduced = tuple(item for item in core if item is not category)
            assert _core_status(
                "sensitive_enterprise_api",
                "cloud-orchestrator",
                decision.profile_id,
                reduced,
            ) == z3.sat


def test_critical_scenario_strict_requirements() -> None:
    result = _load_result("critical_edge_command", "cloud-orchestrator")

    assert result.safe_profile_ids == ("P4",)
    for profile_id in result.safe_profile_ids:
        profile = CATALOG.get_profile(profile_id)
        assert profile.fallback_rule is FallbackRule.FORBIDDEN
        assert profile.resumption_rule is ResumptionRule.FORBIDDEN
        assert profile.lease_strictness is LeaseStrictness.SHORT


def test_deterministic_compilation_bytes() -> None:
    first = _load_result("low_risk_public_tool", "public-tool-agent")
    second = _load_result("low_risk_public_tool", "public-tool-agent")

    assert first.compilation_hash == second.compilation_hash
    assert first.canonical_bytes() == second.canonical_bytes()


def test_duplicate_and_unknown_policy_yaml_fields(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("policy_id: a\npolicy_id: b\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_agent_policy(duplicate)

    unknown = tmp_path / "unknown.yaml"
    text = (POLICIES / "public_tool_agent.yaml").read_text(encoding="utf-8")
    unknown.write_text(text + "unknown_field: true\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_agent_policy(unknown)


def test_requirement_dominance_for_sensitive_derivation() -> None:
    policy = load_agent_policy(POLICIES / "cloud_orchestrator.yaml")
    low = load_scenario(SCENARIOS / "low_risk_public_tool.yaml")
    high = load_scenario(SCENARIOS / "sensitive_enterprise_api.yaml")

    assert requirement_dominates(
        derive_requirement(policy, high.task).final_requirement,
        derive_requirement(policy, low.task).final_requirement,
    )
