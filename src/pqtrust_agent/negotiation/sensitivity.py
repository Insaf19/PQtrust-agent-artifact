"""Deterministic uncertainty and weight sensitivity analyses."""

from __future__ import annotations

from collections import Counter
from decimal import Decimal
from typing import Any

from pqtrust_agent.models.preference import AgentCostPreference
from pqtrust_agent.models.selection import (
    BilateralSelectionInput,
    SelectionMode,
    classify_selection_mode,
)
from pqtrust_agent.negotiation.cost_evidence import METRICS, MetricName, SelectorCostEvidence
from pqtrust_agent.negotiation.normalization import compute_global_anchors, normalize_vector
from pqtrust_agent.negotiation.pareto import pareto_filter
from pqtrust_agent.negotiation.regret import compute_regret_rows, minimax_regret_select
from pqtrust_agent.negotiation.selector import common_safe_set, select_from_safe_set


def _vectors_for_uncertainty_case(
    evidence: SelectorCostEvidence,
    case: str,
) -> dict[str, dict[MetricName, Decimal]]:
    vectors: dict[str, dict[MetricName, Decimal]] = {}
    for profile in evidence.profiles:
        if case == "point":
            vector = profile.measured_vector("point")
        elif case == "all_lower":
            vector = profile.measured_vector("lower")
        elif case == "all_upper":
            vector = profile.measured_vector("upper")
        else:
            mode, metric = case.split(":", 1)
            lower = profile.measured_vector("lower")
            upper = profile.measured_vector("upper")
            point = profile.measured_vector("point")
            vector = {}
            for name in METRICS:
                if name == "total_handshake_bytes":
                    vector[name] = point[name]
                elif mode == "one_lower_others_upper":
                    vector[name] = lower[name] if name == metric else upper[name]
                elif mode == "one_upper_others_lower":
                    vector[name] = upper[name] if name == metric else lower[name]
                else:
                    raise ValueError(f"unknown uncertainty case: {case}")
        vectors[profile.profile_id] = vector
    return vectors


def _select_with_vectors(
    *,
    common: tuple[str, ...],
    all_vectors: dict[str, dict[MetricName, Decimal]],
    evidence: SelectorCostEvidence,
    initiator_preference: AgentCostPreference,
    responder_preference: AgentCostPreference,
) -> tuple[str, tuple[str, ...]]:
    anchors = compute_global_anchors_with_vectors(evidence, all_vectors)
    raw = {profile_id: all_vectors[profile_id] for profile_id in common}
    normalized = {profile_id: normalize_vector(raw[profile_id], anchors) for profile_id in common}
    frontier, _ = pareto_filter(common, raw)
    rows = compute_regret_rows(frontier, normalized, initiator_preference, responder_preference)
    return minimax_regret_select(rows)


def compute_global_anchors_with_vectors(
    evidence: SelectorCostEvidence,
    vectors: dict[str, dict[MetricName, Decimal]],
) -> Any:
    """Compute anchors from explicit P0-P4 vectors."""

    del evidence
    from pqtrust_agent.negotiation.normalization import NormalizationAnchors

    minima: dict[MetricName, Decimal] = {}
    maxima: dict[MetricName, Decimal] = {}
    for metric in METRICS:
        values = [vector[metric] for vector in vectors.values()]
        minimum = min(values)
        maximum = max(values)
        if minimum == maximum:
            raise ValueError(f"normalization denominator is zero for {metric}")
        minima[metric] = minimum
        maxima[metric] = maximum
    return NormalizationAnchors(minima=minima, maxima=maxima)


def uncertainty_sensitivity(
    *,
    selection_input: BilateralSelectionInput,
    scenario_id: str,
    catalog_profile_ids: tuple[str, ...],
    initiator_safe_set: tuple[str, ...],
    responder_safe_set: tuple[str, ...],
    initiator_preference: AgentCostPreference,
    responder_preference: AgentCostPreference,
    cost_evidence: SelectorCostEvidence,
    primary_selected_profile_id: str,
) -> dict[str, Any]:
    """Recompute selection under deterministic evidence-supported cost corners."""

    del selection_input, scenario_id
    common = common_safe_set(catalog_profile_ids, initiator_safe_set, responder_safe_set)
    point_vectors = _vectors_for_uncertainty_case(cost_evidence, "point")
    point_frontier, _ = pareto_filter(
        common,
        {profile_id: point_vectors[profile_id] for profile_id in common},
    )
    selection_mode = classify_selection_mode(
        common_safe_candidate_count=len(common),
        pareto_candidate_count=len(point_frontier),
    )
    cases = ["point", "all_lower", "all_upper"]
    for metric in ("wall_time", "process_cpu_time"):
        cases.append(f"one_lower_others_upper:{metric}")
        cases.append(f"one_upper_others_lower:{metric}")
    selected_by_case: dict[str, str] = {}
    for case in cases:
        selected, _ = _select_with_vectors(
            common=common,
            all_vectors=_vectors_for_uncertainty_case(cost_evidence, case),
            evidence=cost_evidence,
            initiator_preference=initiator_preference,
            responder_preference=responder_preference,
        )
        selected_by_case[case] = selected
    alternatives = sorted(set(selected_by_case.values()) - {primary_selected_profile_id})
    structurally_robust = selection_mode is not SelectionMode.BILATERAL_MINIMAX_REGRET
    if selection_mode is SelectionMode.SINGLETON_COMMON_SAFE_SET:
        classification = SelectionMode.SINGLETON_COMMON_SAFE_SET.value
    elif selection_mode is SelectionMode.PARETO_FRONTIER_COLLAPSE:
        classification = SelectionMode.PARETO_FRONTIER_COLLAPSE.value
    elif all(profile_id == primary_selected_profile_id for profile_id in selected_by_case.values()):
        classification = "uncertainty_robust_selection"
    else:
        classification = "uncertainty_sensitive_selection"
    return {
        "selected_profile_by_case": selected_by_case,
        "same_profile_selected_in_all_cases": len(set(selected_by_case.values())) == 1,
        "robust_selection": all(
            profile_id == primary_selected_profile_id for profile_id in selected_by_case.values()
        ),
        "alternative_profiles_encountered": alternatives,
        "classification": classification,
        "robustness_is_structural": structurally_robust,
        "robustness_is_preference_based": False,
        "robustness_is_uncertainty_based": (
            classification == "uncertainty_robust_selection"
        ),
    }


def weight_grid() -> tuple[tuple[int, int, int], ...]:
    """Return deterministic basis-point triples in increments of 1000."""

    triples: list[tuple[int, int, int]] = []
    for wall in range(0, 10001, 1000):
        for cpu in range(0, 10001 - wall, 1000):
            bytes_weight = 10000 - wall - cpu
            triples.append((wall, cpu, bytes_weight))
    return tuple(triples)


def _grid_preference(agent_id: str, weights: tuple[int, int, int]) -> AgentCostPreference:
    return AgentCostPreference(
        preference_id=f"{agent_id}-sensitivity-{weights[0]}-{weights[1]}-{weights[2]}",
        preference_version=1,
        agent_id=agent_id,
        wall_time_weight_bps=weights[0],
        process_cpu_time_weight_bps=weights[1],
        total_handshake_bytes_weight_bps=weights[2],
        description="Deterministic selector weight-sensitivity grid point.",
    )


def weight_sensitivity(
    *,
    selection_input: BilateralSelectionInput,
    scenario_id: str,
    catalog_profile_ids: tuple[str, ...],
    initiator_safe_set: tuple[str, ...],
    responder_safe_set: tuple[str, ...],
    initiator_agent_id: str,
    responder_agent_id: str,
    cost_evidence: SelectorCostEvidence,
    primary_selected_profile_id: str,
) -> dict[str, Any]:
    """Run deterministic initiator/responder basis-point grid sensitivity."""

    anchors = compute_global_anchors(cost_evidence.profiles)
    grid = weight_grid()
    counts: Counter[str] = Counter()
    common = common_safe_set(catalog_profile_ids, initiator_safe_set, responder_safe_set)
    raw_vectors = {
        profile.profile_id: profile.measured_vector("point") for profile in cost_evidence.profiles
    }
    frontier, _ = pareto_filter(
        common,
        {profile_id: raw_vectors[profile_id] for profile_id in common},
    )
    selection_mode = classify_selection_mode(
        common_safe_candidate_count=len(common),
        pareto_candidate_count=len(frontier),
    )
    for initiator_weights in grid:
        initiator = _grid_preference(initiator_agent_id, initiator_weights)
        for responder_weights in grid:
            responder = _grid_preference(responder_agent_id, responder_weights)
            result = select_from_safe_set(
                scenario_id=scenario_id,
                selection_input=selection_input,
                catalog_profile_ids=catalog_profile_ids,
                initiator_safe_set=initiator_safe_set,
                responder_safe_set=responder_safe_set,
                initiator_preference=initiator,
                responder_preference=responder,
                cost_evidence=cost_evidence,
                anchors=anchors,
            )
            counts[result.selected_profile_id] += 1
    selected_profiles = sorted(counts)
    structurally_robust = selection_mode is not SelectionMode.BILATERAL_MINIMAX_REGRET
    if selection_mode is SelectionMode.SINGLETON_COMMON_SAFE_SET:
        classification = SelectionMode.SINGLETON_COMMON_SAFE_SET.value
    elif selection_mode is SelectionMode.PARETO_FRONTIER_COLLAPSE:
        classification = SelectionMode.PARETO_FRONTIER_COLLAPSE.value
    elif selected_profiles == [primary_selected_profile_id]:
        classification = "preference_robust_selection"
    else:
        classification = "preference_sensitive_selection"
    return {
        "grid_increment_bps": 1000,
        "grid_point_count_per_agent": len(grid),
        "joint_grid_evaluations": len(grid) * len(grid),
        "selected_profile_frequencies": dict(sorted(counts.items())),
        "primary_selected_profile_remains_selected": counts[primary_selected_profile_id] > 0,
        "profiles_that_can_become_selected": selected_profiles,
        "classification": classification,
        "robustness_is_structural": structurally_robust,
        "robustness_is_preference_based": (
            classification == "preference_robust_selection"
        ),
        "robustness_is_uncertainty_based": False,
    }
