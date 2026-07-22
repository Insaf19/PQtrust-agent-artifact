"""Bilateral measured-cost Pareto and minimax-regret selector."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pqtrust_agent.models.compilation import PolicyCompilationResult
from pqtrust_agent.models.preference import AgentCostPreference
from pqtrust_agent.models.scenario import ScenarioDefinition
from pqtrust_agent.models.selection import (
    BilateralCandidateEvaluation,
    BilateralSelectionInput,
    BilateralSelectionResult,
    classify_selection_mode,
    selection_hash,
)
from pqtrust_agent.negotiation.cost_evidence import MetricName, SelectorCostEvidence
from pqtrust_agent.negotiation.normalization import (
    NormalizationAnchors,
    compute_global_anchors,
    normalize_vector,
)
from pqtrust_agent.negotiation.pareto import pareto_filter
from pqtrust_agent.negotiation.regret import RegretRow, compute_regret_rows, minimax_regret_select


def common_safe_set(
    catalog_profile_ids: tuple[str, ...],
    initiator_safe: tuple[str, ...],
    responder_safe: tuple[str, ...],
) -> tuple[str, ...]:
    """Intersect local hard-safe sets in canonical catalog order."""

    return tuple(
        profile_id
        for profile_id in catalog_profile_ids
        if profile_id in initiator_safe and profile_id in responder_safe
    )


def _raw_vectors(
    evidence: SelectorCostEvidence,
    profile_ids: tuple[str, ...] | None = None,
    *,
    case: str = "point",
) -> dict[str, dict[MetricName, Decimal]]:
    wanted = set(profile_ids) if profile_ids is not None else None
    return {
        profile.profile_id: profile.measured_vector(case)
        for profile in evidence.profiles
        if wanted is None or profile.profile_id in wanted
    }


def _candidate_evaluations(
    rows: tuple[RegretRow, ...],
    raw_vectors: dict[str, dict[MetricName, Decimal]],
    normalized_vectors: dict[str, dict[MetricName, Decimal]],
    common: tuple[str, ...],
    removed: dict[str, Any],
) -> tuple[BilateralCandidateEvaluation, ...]:
    by_row = {row.profile_id: row for row in rows}
    evaluations: list[BilateralCandidateEvaluation] = []
    for profile_id in common:
        row = by_row.get(profile_id)
        if row is not None:
            evaluations.append(
                BilateralCandidateEvaluation(
                    profile_id=row.profile_id,
                    raw_measured_cost_vector={
                        str(key): value for key, value in raw_vectors[row.profile_id].items()
                    },
                    normalized_cost_vector={
                        str(key): value for key, value in normalized_vectors[row.profile_id].items()
                    },
                    initiator_weighted_components={
                        str(key): value for key, value in row.initiator_cost.components.items()
                    },
                    responder_weighted_components={
                        str(key): value for key, value in row.responder_cost.components.items()
                    },
                    initiator_cost=row.initiator_cost.total,
                    responder_cost=row.responder_cost.total,
                    initiator_regret=row.initiator_regret,
                    responder_regret=row.responder_regret,
                    maximum_regret=row.maximum_regret,
                    total_regret=row.total_regret,
                    pareto_status="frontier",
                    domination_explanation=None,
                    eligible_for_regret_computation=True,
                    regret_exclusion_reason=None,
                )
            )
            continue
        explanation = removed[profile_id]
        evaluations.append(
            BilateralCandidateEvaluation(
                profile_id=profile_id,
                raw_measured_cost_vector={
                    str(key): value for key, value in raw_vectors[profile_id].items()
                },
                normalized_cost_vector={
                    str(key): value for key, value in normalized_vectors[profile_id].items()
                },
                pareto_status="dominated",
                dominating_profile_ids=explanation.dominating_profile_ids,
                dominated_dimensions=explanation.dominated_dimensions,
                domination_explanation=explanation.as_dict(),
                eligible_for_regret_computation=False,
                regret_exclusion_reason="removed_by_measured_pareto_dominance",
            )
        )
    return tuple(evaluations)


def select_from_safe_set(
    *,
    scenario_id: str,
    selection_input: BilateralSelectionInput,
    catalog_profile_ids: tuple[str, ...],
    initiator_safe_set: tuple[str, ...],
    responder_safe_set: tuple[str, ...],
    initiator_preference: AgentCostPreference,
    responder_preference: AgentCostPreference,
    cost_evidence: SelectorCostEvidence,
    anchors: NormalizationAnchors | None = None,
    case: str = "point",
) -> BilateralSelectionResult:
    """Run Pareto filtering and bilateral minimax-regret selection."""

    common = common_safe_set(catalog_profile_ids, initiator_safe_set, responder_safe_set)
    if not common:
        raise ValueError("bilateral common-safe set is empty")
    all_raw_vectors = _raw_vectors(cost_evidence, case=case)
    raw_vectors = {profile_id: all_raw_vectors[profile_id] for profile_id in common}
    normalizer = (
        anchors
        if anchors is not None
        else compute_global_anchors(cost_evidence.profiles, case=case)
    )
    normalized_vectors = {
        profile_id: normalize_vector(raw_vectors[profile_id], normalizer)
        for profile_id in common
    }
    frontier, removed = pareto_filter(common, raw_vectors)
    rows = compute_regret_rows(
        frontier,
        normalized_vectors,
        initiator_preference,
        responder_preference,
    )
    selected, trace = minimax_regret_select(rows)
    candidates = _candidate_evaluations(rows, raw_vectors, normalized_vectors, common, removed)
    selection_mode = classify_selection_mode(
        common_safe_candidate_count=len(common),
        pareto_candidate_count=len(frontier),
    )
    hash_payload = BilateralSelectionResult.compute_hash_payload(
        selector_schema_version="1.0",
        selector_implementation_version="0.4.0",
        selection_input=selection_input.model_dump(mode="python"),
        scenario_id=scenario_id,
        initiator_local_safe_set=initiator_safe_set,
        responder_local_safe_set=responder_safe_set,
        common_safe_set=common,
        pareto_frontier=frontier,
        removed_as_dominated=tuple(removed),
        selected_profile_id=selected,
        candidates=[candidate.model_dump(mode="python") for candidate in candidates],
        common_safe_candidate_count=len(common),
        pareto_candidate_count=len(frontier),
        selection_mode=selection_mode.value,
        minimax_regret_exercised=len(frontier) >= 2,
        bilateral_tradeoff_present=len(frontier) >= 2,
        frontier_collapsed=len(frontier) == 1,
        deterministic_tie_break_trace=trace,
        normalization_anchors=normalizer.as_dict(),
        absolute_timing_stability_passed=cost_evidence.absolute_timing_stability_passed,
        paired_relative_timing_stability_passed=cost_evidence.paired_relative_timing_stability_passed,
        relative_cost_usable_for_selector=cost_evidence.relative_cost_usable_for_selector,
    )
    return BilateralSelectionResult(
        scenario_id=scenario_id,
        initiator_local_safe_set=initiator_safe_set,
        responder_local_safe_set=responder_safe_set,
        common_safe_set=common,
        pareto_frontier=frontier,
        removed_as_dominated=tuple(removed),
        selected_profile_id=selected,
        candidates=candidates,
        common_safe_candidate_count=len(common),
        pareto_candidate_count=len(frontier),
        selection_mode=selection_mode,
        minimax_regret_exercised=len(frontier) >= 2,
        bilateral_tradeoff_present=len(frontier) >= 2,
        frontier_collapsed=len(frontier) == 1,
        deterministic_tie_break_trace=trace,
        absolute_timing_stability_passed=cost_evidence.absolute_timing_stability_passed,
        paired_relative_timing_stability_passed=cost_evidence.paired_relative_timing_stability_passed,
        relative_cost_usable_for_selector=cost_evidence.relative_cost_usable_for_selector,
        selection_hash=selection_hash(hash_payload),
    )


def build_selection_input(
    *,
    scenario: ScenarioDefinition,
    catalog_hash: str,
    initiator_compilation: PolicyCompilationResult,
    responder_compilation: PolicyCompilationResult,
    initiator_preference: AgentCostPreference,
    responder_preference: AgentCostPreference,
    cost_evidence: SelectorCostEvidence,
) -> BilateralSelectionInput:
    """Construct the auditable immutable selector input record."""

    return BilateralSelectionInput(
        scenario_hash=scenario.scenario_hash(),
        task_hash=scenario.task.context_hash(),
        catalog_hash=catalog_hash,
        initiator_agent_id=scenario.initiator_agent_id,
        responder_agent_id=scenario.responder_agent_id,
        initiator_policy_compilation_hash=initiator_compilation.compilation_hash,
        responder_policy_compilation_hash=responder_compilation.compilation_hash,
        initiator_preference_hash=initiator_preference.preference_hash(),
        responder_preference_hash=responder_preference.preference_hash(),
        calibrated_cost_evidence_hash=cost_evidence.evidence_hash,
        evaluation_time=scenario.evaluation_time_utc,
    )


def run_bilateral_selector(
    *,
    scenario: ScenarioDefinition,
    catalog_profile_ids: tuple[str, ...],
    catalog_hash: str,
    initiator_compilation: PolicyCompilationResult,
    responder_compilation: PolicyCompilationResult,
    initiator_preference: AgentCostPreference,
    responder_preference: AgentCostPreference,
    cost_evidence: SelectorCostEvidence,
) -> BilateralSelectionResult:
    """Run the primary point-estimate bilateral selector."""

    selection_input = build_selection_input(
        scenario=scenario,
        catalog_hash=catalog_hash,
        initiator_compilation=initiator_compilation,
        responder_compilation=responder_compilation,
        initiator_preference=initiator_preference,
        responder_preference=responder_preference,
        cost_evidence=cost_evidence,
    )
    return select_from_safe_set(
        scenario_id=scenario.scenario_id,
        selection_input=selection_input,
        catalog_profile_ids=catalog_profile_ids,
        initiator_safe_set=initiator_compilation.safe_profile_ids,
        responder_safe_set=responder_compilation.safe_profile_ids,
        initiator_preference=initiator_preference,
        responder_preference=responder_preference,
        cost_evidence=cost_evidence,
    )


def baseline_selectors(
    *,
    common: tuple[str, ...],
    raw_vectors: dict[str, dict[MetricName, Decimal]],
    normalized_vectors: dict[str, dict[MetricName, Decimal]],
    initiator_rows: dict[str, Decimal],
    responder_rows: dict[str, Decimal],
) -> dict[str, dict[str, Any]]:
    """Return deterministic safe-only baseline selector outputs."""

    def choose(name: str, key: Any) -> dict[str, Any]:
        ordered = sorted(common, key=key)
        return {
            "selected_profile_id": ordered[0],
            "trace": [f"{profile_id}: {key(profile_id)}" for profile_id in ordered],
            "common_safe_set": list(common),
        }

    return {
        "initiator_minimum_cost": choose(
            "initiator_minimum_cost",
            lambda profile_id: (initiator_rows[profile_id], profile_id),
        ),
        "responder_minimum_cost": choose(
            "responder_minimum_cost",
            lambda profile_id: (responder_rows[profile_id], profile_id),
        ),
        "minimum_total_cost": choose(
            "minimum_total_cost",
            lambda profile_id: (
                initiator_rows[profile_id] + responder_rows[profile_id],
                profile_id,
            ),
        ),
        "minimum_maximum_raw_normalized_component": choose(
            "minimum_maximum_raw_normalized_component",
            lambda profile_id: (max(normalized_vectors[profile_id].values()), profile_id),
        ),
        "canonical_first_safe": {
            "selected_profile_id": common[0],
            "trace": [f"canonical_order={list(common)}"],
            "common_safe_set": list(common),
        },
    }
