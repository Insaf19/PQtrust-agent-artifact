"""Validation helpers for selector-stage scenarios."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import z3

from pqtrust_agent.evidence.decimal_json import decimal_json_compatible
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.compilation import COMPILER_IMPLEMENTATION_VERSION
from pqtrust_agent.models.preference import AgentCostPreference, load_agent_cost_preference
from pqtrust_agent.models.selection import SELECTOR_IMPLEMENTATION_VERSION, SelectionMode
from pqtrust_agent.negotiation.cost_evidence import (
    MetricName,
    SelectorCostEvidence,
    load_selector_cost_evidence,
)
from pqtrust_agent.negotiation.normalization import compute_global_anchors, normalize_vector
from pqtrust_agent.negotiation.regret import (
    RegretRow,
    compute_regret_rows,
    minimax_regret_select,
    weighted_cost,
)
from pqtrust_agent.negotiation.selector import (
    baseline_selectors,
    build_selection_input,
    common_safe_set,
    run_bilateral_selector,
)
from pqtrust_agent.negotiation.sensitivity import (
    uncertainty_sensitivity,
    weight_grid,
    weight_sensitivity,
)
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario
from pqtrust_agent.policy.validation import validate_mapper_monotonicity


def selector_report_compatible(value: Any) -> Any:
    """Convert selector values to JSON-report-compatible objects."""

    return decimal_json_compatible(value)


def baseline_report(
    *,
    catalog_profile_ids: tuple[str, ...],
    initiator_safe_set: tuple[str, ...],
    responder_safe_set: tuple[str, ...],
    initiator_preference: AgentCostPreference,
    responder_preference: AgentCostPreference,
    cost_evidence: SelectorCostEvidence,
) -> dict[str, Any]:
    """Compute all safe-only baseline selectors for later comparison."""

    common = common_safe_set(catalog_profile_ids, initiator_safe_set, responder_safe_set)
    anchors = compute_global_anchors(cost_evidence.profiles)
    by_profile = cost_evidence.by_profile()
    raw_vectors: dict[str, dict[MetricName, Decimal]] = {
        profile_id: by_profile[profile_id].measured_vector("point") for profile_id in common
    }
    normalized_vectors = {
        profile_id: normalize_vector(raw_vectors[profile_id], anchors) for profile_id in common
    }
    initiator_costs = {
        profile_id: weighted_cost(normalized_vectors[profile_id], initiator_preference).total
        for profile_id in common
    }
    responder_costs = {
        profile_id: weighted_cost(normalized_vectors[profile_id], responder_preference).total
        for profile_id in common
    }
    return baseline_selectors(
        common=common,
        raw_vectors=raw_vectors,
        normalized_vectors=normalized_vectors,
        initiator_rows=initiator_costs,
        responder_rows=responder_costs,
    )


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _agent_file(agent_id: str) -> str:
    return f"{agent_id.replace('-', '_')}.yaml"


def _grid_preference(agent_id: str, weights: tuple[int, int, int]) -> AgentCostPreference:
    return AgentCostPreference(
        preference_id=f"{agent_id}-grid-{weights[0]}-{weights[1]}-{weights[2]}",
        preference_version=1,
        agent_id=agent_id,
        wall_time_weight_bps=weights[0],
        process_cpu_time_weight_bps=weights[1],
        total_handshake_bytes_weight_bps=weights[2],
        description="Deterministic selector preference-conflict grid point.",
    )


def _median(values: list[Decimal]) -> Decimal:
    if not values:
        return Decimal(0)
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / Decimal(2)


def _p95(values: list[Decimal]) -> Decimal:
    if not values:
        return Decimal(0)
    ordered = sorted(values)
    index = (Decimal("0.95") * Decimal(len(ordered) - 1)).to_integral_value()
    return ordered[int(index)]


def _cost_vectors(
    *,
    common: tuple[str, ...],
    cost_evidence: SelectorCostEvidence,
) -> tuple[dict[str, dict[MetricName, Decimal]], dict[str, dict[MetricName, Decimal]]]:
    anchors = compute_global_anchors(cost_evidence.profiles)
    by_profile = cost_evidence.by_profile()
    raw = {
        profile_id: by_profile[profile_id].measured_vector("point") for profile_id in common
    }
    normalized = {profile_id: normalize_vector(raw[profile_id], anchors) for profile_id in common}
    return raw, normalized


def _row_map(rows: tuple[RegretRow, ...]) -> dict[str, RegretRow]:
    return {row.profile_id: row for row in rows}


def _minimum_cost_profile(rows: tuple[RegretRow, ...], side: str) -> str:
    if side == "initiator":
        return sorted(
            rows,
            key=lambda row: (row.initiator_cost.total, row.profile_id),
        )[0].profile_id
    return sorted(rows, key=lambda row: (row.responder_cost.total, row.profile_id))[0].profile_id


def _method_regret(row: RegretRow) -> dict[str, Decimal]:
    return {
        "initiator_regret": row.initiator_regret,
        "responder_regret": row.responder_regret,
        "maximum_regret": row.maximum_regret,
        "total_regret": row.total_regret,
    }


def _evaluate_preference_grid(
    *,
    scenario_report: dict[str, Any],
    cost_evidence: SelectorCostEvidence,
) -> tuple[dict[str, Any], dict[str, Any]]:
    common = tuple(cast(list[str], scenario_report["common_safe_set"]))
    frontier = tuple(cast(list[str], scenario_report["pareto_frontier"]))
    _, normalized = _cost_vectors(common=common, cost_evidence=cost_evidence)
    grid = weight_grid()
    conflict_count = 0
    selected_counts: Counter[str] = Counter()
    initiator_optimum_counts: Counter[str] = Counter()
    responder_optimum_counts: Counter[str] = Counter()
    alternatives: set[str] = set()
    methods = (
        "bilateral_minimax_regret",
        "initiator_minimum_cost",
        "responder_minimum_cost",
        "minimum_total_cost",
        "canonical_first_safe",
    )
    method_maxima: dict[str, list[Decimal]] = {method: [] for method in methods}
    method_totals: dict[str, list[Decimal]] = {method: [] for method in methods}
    improvement_counts: dict[str, int] = {method: 0 for method in methods if method != methods[0]}
    tie_counts: dict[str, int] = {method: 0 for method in methods if method != methods[0]}
    degradation_counts: dict[str, int] = {method: 0 for method in methods if method != methods[0]}
    fairness_gains: dict[str, list[Decimal]] = {
        method: [] for method in methods if method != methods[0]
    }
    negative_gain_counts: dict[str, int] = {method: 0 for method in methods if method != methods[0]}
    validation_errors: list[str] = []
    for initiator_weights in grid:
        initiator = _grid_preference(
            cast(str, scenario_report["initiator_agent_id"]),
            initiator_weights,
        )
        for responder_weights in grid:
            responder = _grid_preference(
                cast(str, scenario_report["responder_agent_id"]),
                responder_weights,
            )
            rows = compute_regret_rows(frontier, normalized, initiator, responder)
            rows_by_profile = _row_map(rows)
            initiator_best = _minimum_cost_profile(rows, "initiator")
            responder_best = _minimum_cost_profile(rows, "responder")
            initiator_optimum_counts[initiator_best] += 1
            responder_optimum_counts[responder_best] += 1
            minimax_selected, _ = minimax_regret_select(rows)
            selected_counts[minimax_selected] += 1
            alternatives.update({initiator_best, responder_best, minimax_selected})
            if initiator_best == responder_best:
                continue
            conflict_count += 1
            method_selection = {
                "bilateral_minimax_regret": minimax_selected,
                "initiator_minimum_cost": initiator_best,
                "responder_minimum_cost": responder_best,
                "minimum_total_cost": sorted(
                    rows,
                    key=lambda row: (
                        row.initiator_cost.total + row.responder_cost.total,
                        row.profile_id,
                    ),
                )[0].profile_id,
                "canonical_first_safe": frontier[0],
            }
            minimax_max = rows_by_profile[minimax_selected].maximum_regret
            for method, profile_id in method_selection.items():
                regret = _method_regret(rows_by_profile[profile_id])
                method_maxima[method].append(regret["maximum_regret"])
                method_totals[method].append(regret["total_regret"])
                if regret["maximum_regret"] < minimax_max:
                    validation_errors.append(
                        "minimax optimality violated by "
                        f"{method} at {initiator_weights}/{responder_weights}"
                    )
                if method == "bilateral_minimax_regret":
                    continue
                gain = regret["maximum_regret"] - minimax_max
                fairness_gains[method].append(gain)
                if gain > 0:
                    improvement_counts[method] += 1
                elif gain == 0:
                    tie_counts[method] += 1
                else:
                    degradation_counts[method] += 1
                    negative_gain_counts[method] += 1
                    validation_errors.append(
                        "negative fairness gain for "
                        f"{method} at {initiator_weights}/{responder_weights}"
                    )
    total_pairs = len(grid) * len(grid)
    no_conflict_count = total_pairs - conflict_count
    preference_report = {
        "scenario_id": scenario_report["scenario_id"],
        "grid_increment_bps": 1000,
        "grid_point_count_per_agent": len(grid),
        "total_joint_preference_pairs": total_pairs,
        "conflict_pair_count": conflict_count,
        "conflict_pair_proportion": Decimal(conflict_count) / Decimal(total_pairs),
        "no_conflict_count": no_conflict_count,
        "selected_profile_frequencies": dict(sorted(selected_counts.items())),
        "individual_optimum_frequencies": {
            "initiator": dict(sorted(initiator_optimum_counts.items())),
            "responder": dict(sorted(responder_optimum_counts.items())),
        },
        "alternative_profiles_encountered": sorted(alternatives),
        "validation_errors": validation_errors,
    }
    fairness_methods: dict[str, Any] = {}
    for method in methods:
        fairness_methods[method] = {
            "median_maximum_regret": _median(method_maxima[method]),
            "p95_maximum_regret": _p95(method_maxima[method]),
            "maximum_observed_maximum_regret": max(method_maxima[method], default=Decimal(0)),
            "median_total_regret": _median(method_totals[method]),
        }
        if method != "bilateral_minimax_regret":
            gains = fairness_gains[method]
            fairness_methods[method].update(
                {
                    "strict_minimax_improvement_count": improvement_counts[method],
                    "tie_count": tie_counts[method],
                    "degradation_count": degradation_counts[method],
                    "fairness_gain": {
                        "minimum_fairness_gain": min(gains, default=Decimal(0)),
                        "median_fairness_gain": _median(gains),
                        "maximum_fairness_gain": max(gains, default=Decimal(0)),
                        "strict_positive_gain_proportion": (
                            Decimal(improvement_counts[method]) / Decimal(conflict_count)
                            if conflict_count
                            else Decimal(0)
                        ),
                        "zero_gain_proportion": (
                            Decimal(tie_counts[method]) / Decimal(conflict_count)
                            if conflict_count
                            else Decimal(0)
                        ),
                        "negative_gain_count": negative_gain_counts[method],
                    },
                }
            )
    fairness_report = {
        "scenario_id": scenario_report["scenario_id"],
        "conflict_pair_count": conflict_count,
        "methods": fairness_methods,
        "validation_errors": validation_errors,
        "validation_passed": not validation_errors,
    }
    return preference_report, fairness_report


def _compile_side(
    *,
    catalog: Any,
    agents_dir: Path,
    policies_dir: Path,
    agent_id: str,
    policy_id: str,
    task: Any,
    evaluation_time: datetime,
    monotonicity_cache: dict[Path, list[str]],
) -> Any:
    manifest = load_agent_manifest(agents_dir / _agent_file(agent_id))
    policy_path = policies_dir / _agent_file(agent_id)
    policy = load_agent_policy(policy_path)
    if policy.policy_id != policy_id:
        raise ValueError(f"{agent_id}: expected policy_id {policy_id}, got {policy.policy_id}")
    if policy_path not in monotonicity_cache:
        monotonicity_cache[policy_path] = validate_mapper_monotonicity(policy)
    if monotonicity_cache[policy_path]:
        raise ValueError("; ".join(monotonicity_cache[policy_path]))
    return compile_local_policy(catalog, manifest, policy, task, evaluation_time)


def validate_selector_stage(
    *,
    catalog_path: Path,
    agents_dir: Path,
    policies_dir: Path,
    preferences_dir: Path,
    scenarios_dir: Path,
    cost_evidence_dir: Path,
) -> dict[str, Any]:
    """Return machine-readable Stage 4B selector validation reports."""

    errors: list[str] = []
    scenario_reports: list[dict[str, Any]] = []
    candidate_audit: list[dict[str, Any]] = []
    catalog = load_profile_catalog(catalog_path)
    catalog_hash = catalog.catalog_hash()
    cost_evidence = load_selector_cost_evidence(cost_evidence_dir, catalog)
    anchors = compute_global_anchors(cost_evidence.profiles)
    monotonicity_cache: dict[Path, list[str]] = {}

    for scenario_path in sorted(scenarios_dir.glob("*.yaml")):
        try:
            scenario = load_scenario(scenario_path)
            initiator_compilation = _compile_side(
                catalog=catalog,
                agents_dir=agents_dir,
                policies_dir=policies_dir,
                agent_id=scenario.initiator_agent_id,
                policy_id=scenario.initiator_policy_id,
                task=scenario.task,
                evaluation_time=scenario.evaluation_time_utc,
                monotonicity_cache=monotonicity_cache,
            )
            responder_compilation = _compile_side(
                catalog=catalog,
                agents_dir=agents_dir,
                policies_dir=policies_dir,
                agent_id=scenario.responder_agent_id,
                policy_id=scenario.responder_policy_id,
                task=scenario.task,
                evaluation_time=scenario.evaluation_time_utc,
                monotonicity_cache=monotonicity_cache,
            )
            initiator_preference = load_agent_cost_preference(
                preferences_dir / _agent_file(scenario.initiator_agent_id)
            )
            responder_preference = load_agent_cost_preference(
                preferences_dir / _agent_file(scenario.responder_agent_id)
            )
            if initiator_preference.agent_id != scenario.initiator_agent_id:
                raise ValueError("initiator preference agent_id mismatch")
            if responder_preference.agent_id != scenario.responder_agent_id:
                raise ValueError("responder preference agent_id mismatch")
            result = run_bilateral_selector(
                scenario=scenario,
                catalog_profile_ids=catalog.profile_ids(),
                catalog_hash=catalog_hash,
                initiator_compilation=initiator_compilation,
                responder_compilation=responder_compilation,
                initiator_preference=initiator_preference,
                responder_preference=responder_preference,
                cost_evidence=cost_evidence,
            )
            if result.selected_profile_id not in initiator_compilation.safe_profile_ids:
                raise ValueError("selected profile is not in initiator safe set")
            if result.selected_profile_id not in responder_compilation.safe_profile_ids:
                raise ValueError("selected profile is not in responder safe set")
            selection_input = build_selection_input(
                scenario=scenario,
                catalog_hash=catalog_hash,
                initiator_compilation=initiator_compilation,
                responder_compilation=responder_compilation,
                initiator_preference=initiator_preference,
                responder_preference=responder_preference,
                cost_evidence=cost_evidence,
            )
            scenario_reports.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "scenario_hash": scenario.scenario_hash(),
                    "task_hash": scenario.task.context_hash(),
                    "initiator_agent_id": scenario.initiator_agent_id,
                    "responder_agent_id": scenario.responder_agent_id,
                    "initiator_local_safe_set": list(initiator_compilation.safe_profile_ids),
                    "responder_local_safe_set": list(responder_compilation.safe_profile_ids),
                    "common_safe_set": list(result.common_safe_set),
                    "common_safe_candidate_count": result.common_safe_candidate_count,
                    "pareto_frontier": list(result.pareto_frontier),
                    "pareto_candidate_count": result.pareto_candidate_count,
                    "selection_mode": result.selection_mode.value,
                    "minimax_regret_exercised": result.minimax_regret_exercised,
                    "bilateral_tradeoff_present": result.bilateral_tradeoff_present,
                    "removed_as_dominated": list(result.removed_as_dominated),
                    "selected_profile_id": result.selected_profile_id,
                    "regret_table": [
                        candidate.model_dump(mode="python")
                        for candidate in result.candidates
                        if candidate.eligible_for_regret_computation
                    ],
                    "candidate_audit": [
                        candidate.model_dump(mode="python") for candidate in result.candidates
                    ],
                    "frontier_collapsed": result.frontier_collapsed,
                    "deterministic_tie_break_trace": list(
                        result.deterministic_tie_break_trace
                    ),
                    "selection_hash": result.selection_hash,
                    "uncertainty_sensitivity": uncertainty_sensitivity(
                        selection_input=selection_input,
                        scenario_id=scenario.scenario_id,
                        catalog_profile_ids=catalog.profile_ids(),
                        initiator_safe_set=initiator_compilation.safe_profile_ids,
                        responder_safe_set=responder_compilation.safe_profile_ids,
                        initiator_preference=initiator_preference,
                        responder_preference=responder_preference,
                        cost_evidence=cost_evidence,
                        primary_selected_profile_id=result.selected_profile_id,
                    ),
                    "weight_sensitivity": weight_sensitivity(
                        selection_input=selection_input,
                        scenario_id=scenario.scenario_id,
                        catalog_profile_ids=catalog.profile_ids(),
                        initiator_safe_set=initiator_compilation.safe_profile_ids,
                        responder_safe_set=responder_compilation.safe_profile_ids,
                        initiator_agent_id=scenario.initiator_agent_id,
                        responder_agent_id=scenario.responder_agent_id,
                        cost_evidence=cost_evidence,
                        primary_selected_profile_id=result.selected_profile_id,
                    ),
                    "baseline_selections": baseline_report(
                        catalog_profile_ids=catalog.profile_ids(),
                        initiator_safe_set=initiator_compilation.safe_profile_ids,
                        responder_safe_set=responder_compilation.safe_profile_ids,
                        initiator_preference=initiator_preference,
                        responder_preference=responder_preference,
                        cost_evidence=cost_evidence,
                    ),
                }
            )
            candidate_audit.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "scenario_type": "capability_ablation"
                    if scenario.scenario_id == "low-risk-quantum-ready-tool"
                    else "primary",
                    "common_safe_set": list(result.common_safe_set),
                    "pareto_frontier": list(result.pareto_frontier),
                    "candidates": [
                        candidate.model_dump(mode="python") for candidate in result.candidates
                    ],
                }
            )
        except Exception as exc:
            errors.append(f"{scenario_path}: {exc}")

    reports_by_id = {report["scenario_id"]: report for report in scenario_reports}
    primary_ids = {
        "critical-edge-command",
        "low-risk-public-tool",
        "sensitive-enterprise-api",
    }
    ablation_id = "low-risk-quantum-ready-tool"
    missing_primary = sorted(primary_ids - set(reports_by_id))
    if missing_primary:
        errors.append(f"missing primary scenarios: {missing_primary}")
    if ablation_id not in reports_by_id:
        errors.append(f"missing capability-ablation scenario: {ablation_id}")
    preference_report: dict[str, Any] = {
        "scenario_id": ablation_id,
        "validation_errors": ["ablation scenario unavailable"],
        "validation_passed": False,
    }
    fairness_report: dict[str, Any] = {
        "scenario_id": ablation_id,
        "validation_errors": ["ablation scenario unavailable"],
        "validation_passed": False,
    }
    nondegenerate_report: dict[str, Any] = {
        "scenario_id": ablation_id,
        "validation_errors": ["ablation scenario unavailable"],
        "validation_passed": False,
    }
    if ablation_id in reports_by_id:
        ablation = reports_by_id[ablation_id]
        ablation_errors: list[str] = []
        if ablation["common_safe_set"] != ["P0", "P1", "P3"]:
            ablation_errors.append("common safe set is not P0/P1/P3")
        if ablation["pareto_frontier"] != ["P0", "P3"]:
            ablation_errors.append("measured Pareto frontier is not P0/P3")
        if ablation["common_safe_candidate_count"] < 3:
            ablation_errors.append("common safe set has fewer than three profiles")
        if ablation["pareto_candidate_count"] < 2:
            ablation_errors.append("Pareto frontier has fewer than two profiles")
        if ablation["selection_mode"] != SelectionMode.BILATERAL_MINIMAX_REGRET.value:
            ablation_errors.append("selection mode is not bilateral_minimax_regret")
        if ablation["minimax_regret_exercised"] is not True:
            ablation_errors.append("minimax regret was not exercised")
        if not ablation["removed_as_dominated"]:
            ablation_errors.append("no candidate was removed through measured Pareto dominance")
        audit_by_profile = {
            item["profile_id"]: item
            for item in cast(list[dict[str, Any]], ablation["candidate_audit"])
        }
        if audit_by_profile.get("P1", {}).get("pareto_status") != "dominated":
            ablation_errors.append("P1 domination was not derived from loaded evidence")
        if any(
            profile_id not in ablation["initiator_local_safe_set"]
            or profile_id not in ablation["responder_local_safe_set"]
            for profile_id in ablation["common_safe_set"]
        ):
            ablation_errors.append("common-safe candidate is not hard-safe for both agents")
        preference_report, fairness_report = _evaluate_preference_grid(
            scenario_report=ablation,
            cost_evidence=cost_evidence,
        )
        ablation_errors.extend(cast(list[str], preference_report["validation_errors"]))
        ablation_errors.extend(cast(list[str], fairness_report["validation_errors"]))
        selected_audit = audit_by_profile[cast(str, ablation["selected_profile_id"])]
        regret_table = cast(list[dict[str, Any]], ablation["regret_table"])
        initiator_optimum = sorted(
            regret_table,
            key=lambda item: (cast(Decimal, item["initiator_cost"]), cast(str, item["profile_id"])),
        )[0]
        responder_optimum = sorted(
            regret_table,
            key=lambda item: (cast(Decimal, item["responder_cost"]), cast(str, item["profile_id"])),
        )[0]
        nondegenerate_report = {
            "scenario_id": ablation_id,
            "common_safe_set": ablation["common_safe_set"],
            "pareto_frontier": ablation["pareto_frontier"],
            "selection_mode": ablation["selection_mode"],
            "minimax_regret_exercised": ablation["minimax_regret_exercised"],
            "registered_preference_result": {
                "selected_profile_id": ablation["selected_profile_id"],
                "initiator_cost": selected_audit["initiator_cost"],
                "responder_cost": selected_audit["responder_cost"],
                "initiator_regret": selected_audit["initiator_regret"],
                "responder_regret": selected_audit["responder_regret"],
                "maximum_regret": selected_audit["maximum_regret"],
                "total_regret": selected_audit["total_regret"],
                "tie_break_trace": ablation["deterministic_tie_break_trace"],
                "registered_preferences_conflict": (
                    initiator_optimum["profile_id"] != responder_optimum["profile_id"]
                ),
                "selected_profile_differs_from_either_unilateral_optimum": (
                    selected_audit["profile_id"] != initiator_optimum["profile_id"]
                    or selected_audit["profile_id"] != responder_optimum["profile_id"]
                ),
                "initiator_unilateral_optimum": initiator_optimum["profile_id"],
                "responder_unilateral_optimum": responder_optimum["profile_id"],
            },
            "validation_errors": ablation_errors,
            "validation_passed": not ablation_errors,
        }
        errors.extend(ablation_errors)

    main_report = {
        "report_timestamp_utc": _timestamp(),
        "selector_implementation_version": SELECTOR_IMPLEMENTATION_VERSION,
        "compiler_implementation_version": COMPILER_IMPLEMENTATION_VERSION,
        "z3_version": z3.get_version_string(),
        "catalog_hash": catalog_hash,
        "cost_evidence_hash": cost_evidence.evidence_hash,
        "normalization_anchors": anchors.as_dict(),
        "scenario_count": len(scenario_reports),
        "primary_scenario_count": len(
            [report for report in scenario_reports if report["scenario_id"] in primary_ids]
        ),
        "capability_ablation_scenario_count": len(
            [report for report in scenario_reports if report["scenario_id"] == ablation_id]
        ),
        "scenarios": scenario_reports,
        "selector_stage_conclusion": {
            "hard_safety_validated": not any(
                profile_id not in report["initiator_local_safe_set"]
                or profile_id not in report["responder_local_safe_set"]
                for report in scenario_reports
                for profile_id in report["common_safe_set"]
            ),
            "measured_cost_pipeline_validated": cost_evidence.relative_cost_usable_for_selector,
            "minimax_implementation_validated": not cast(
                list[str],
                fairness_report.get("validation_errors", []),
            ),
            "nondegenerate_minimax_exercised": nondegenerate_report.get(
                "validation_passed",
                False,
            ),
            "exhaustive_preference_evaluation_completed": preference_report.get(
                "total_joint_preference_pairs"
            )
            == 4356,
            "validation_passed": False,
        },
        "validation_errors": errors,
        "validation_passed": not errors
        and len(scenario_reports) == 4
        and nondegenerate_report.get("validation_passed") is True
        and fairness_report.get("validation_passed") is True,
    }
    main_report["selector_stage_conclusion"]["validation_passed"] = main_report[
        "validation_passed"
    ]
    return cast(
        dict[str, Any],
        selector_report_compatible(
            {
                "selector_stage_validation.json": main_report,
                "selector_candidate_audit.json": {
                    "report_timestamp_utc": main_report["report_timestamp_utc"],
                    "scenarios": candidate_audit,
                },
                "nondegenerate_frontier_evaluation.json": nondegenerate_report,
                "preference_conflict_evaluation.json": preference_report,
                "fairness_comparison.json": fairness_report,
            }
        ),
    )
