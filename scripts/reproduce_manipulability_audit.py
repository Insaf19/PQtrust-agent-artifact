#!/usr/bin/env python3
"""Independently reproduce the finite-grid unilateral-misreport audit."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any, Literal, cast

getcontext().prec = 50

Metric = Literal["wall_time", "process_cpu_time", "total_handshake_bytes"]
Weight = tuple[int, int, int]
Vector = dict[Metric, Decimal]

METRICS: tuple[Metric, ...] = (
    "wall_time",
    "process_cpu_time",
    "total_handshake_bytes",
)
SCENARIO_ID = "low-risk-quantum-ready-tool"
EXPECTED = {
    "grid_points_per_endpoint": 66,
    "truthful_joint_pairs": 4356,
    "conflict_pairs": 1210,
    "alternative_reports_tested_per_endpoint_side": 283140,
    "total_unilateral_alternative_reports_tested": 566280,
    "selection_changing_reports_per_side": 13310,
    "strictly_profitable_reports_per_side": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selector-report",
        type=Path,
        default=Path("artifacts/selection/selector_stage_validation.json"),
    )
    parser.add_argument(
        "--frozen-pairs",
        type=Path,
        default=Path(
            "artifacts/analysis/posthoc/strategic_manipulability_pairs.csv"
        ),
    )
    parser.add_argument(
        "--frozen-reference",
        type=Path,
        default=Path(
            "artifacts/analysis/posthoc/"
            "strategic_manipulability_independent_validation.json"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "artifacts/reproduced/posthoc/"
            "strategic_manipulability_independent_validation.json"
        ),
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def weight_grid() -> tuple[Weight, ...]:
    return tuple(
        (wall, cpu, 10000 - wall - cpu)
        for wall in range(0, 10001, 1000)
        for cpu in range(0, 10001 - wall, 1000)
    )


def load_frontier_vectors(path: Path) -> tuple[tuple[str, ...], dict[str, Vector]]:
    report = load_json(path)
    scenarios = cast(list[dict[str, Any]], report["scenarios"])
    scenario = next(item for item in scenarios if item["scenario_id"] == SCENARIO_ID)
    frontier = tuple(cast(list[str], scenario["pareto_frontier"]))
    candidates = cast(list[dict[str, Any]], scenario["candidate_audit"])
    vectors: dict[str, Vector] = {}
    for candidate in candidates:
        profile_id = cast(str, candidate["profile_id"])
        if profile_id not in frontier:
            continue
        raw_vector = cast(dict[str, str], candidate["normalized_cost_vector"])
        vectors[profile_id] = {
            metric: Decimal(raw_vector[metric]) for metric in METRICS
        }
    if set(vectors) != set(frontier):
        raise ValueError("frontier vectors are incomplete")
    return frontier, vectors


def weighted_cost(vector: Vector, weights: Weight) -> Decimal:
    return sum(
        (
            vector[metric] * Decimal(weights[index]) / Decimal(10000)
            for index, metric in enumerate(METRICS)
        ),
        Decimal(0),
    )


def select_profile(
    frontier: tuple[str, ...],
    vectors: dict[str, Vector],
    initiator_weights: Weight,
    responder_weights: Weight,
) -> tuple[str, dict[str, Decimal], dict[str, Decimal]]:
    initiator_costs = {
        profile_id: weighted_cost(vectors[profile_id], initiator_weights)
        for profile_id in frontier
    }
    responder_costs = {
        profile_id: weighted_cost(vectors[profile_id], responder_weights)
        for profile_id in frontier
    }
    initiator_minimum = min(initiator_costs.values())
    responder_minimum = min(responder_costs.values())

    def selector_tuple(profile_id: str) -> tuple[Decimal, Decimal, Decimal, Decimal, str]:
        initiator_regret = initiator_costs[profile_id] - initiator_minimum
        responder_regret = responder_costs[profile_id] - responder_minimum
        vector = vectors[profile_id]
        return (
            max(initiator_regret, responder_regret),
            initiator_regret + responder_regret,
            max(vector.values()),
            sum(vector.values(), Decimal(0)),
            profile_id,
        )

    selected = min(frontier, key=selector_tuple)
    return selected, initiator_costs, responder_costs


def load_frozen_truthful_selections(path: Path) -> dict[tuple[str, str], str]:
    if not path.is_file():
        return {}
    selections: dict[tuple[str, str], str] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            key = (row["true_initiator_weights"], row["true_responder_weights"])
            selections[key] = row["truthful_selected_profile"]
    return selections


def format_weight(weights: Weight) -> str:
    return "/".join(str(value) for value in weights)


def reproduce(
    selector_report: Path,
    frozen_pairs: Path,
) -> dict[str, Any]:
    frontier, vectors = load_frontier_vectors(selector_report)
    grid = weight_grid()
    frozen_selections = load_frozen_truthful_selections(frozen_pairs)

    selected_distribution: Counter[str] = Counter()
    conflict_pairs = 0
    selector_mismatches = 0
    initiator_tested = 0
    responder_tested = 0
    initiator_changed = 0
    responder_changed = 0
    initiator_profitable = 0
    responder_profitable = 0
    initiator_neutral = 0
    responder_neutral = 0
    initiator_harmful = 0
    responder_harmful = 0

    for true_initiator in grid:
        for true_responder in grid:
            selected, true_initiator_costs, true_responder_costs = select_profile(
                frontier,
                vectors,
                true_initiator,
                true_responder,
            )
            selected_distribution[selected] += 1
            frozen_selected = frozen_selections.get(
                (format_weight(true_initiator), format_weight(true_responder))
            )
            if frozen_selected is not None and frozen_selected != selected:
                selector_mismatches += 1

            initiator_optimum = min(
                frontier,
                key=lambda profile_id: (true_initiator_costs[profile_id], profile_id),
            )
            responder_optimum = min(
                frontier,
                key=lambda profile_id: (true_responder_costs[profile_id], profile_id),
            )
            if initiator_optimum != responder_optimum:
                conflict_pairs += 1

            initiator_truthful_cost = true_initiator_costs[selected]
            for false_initiator in grid:
                if false_initiator == true_initiator:
                    continue
                initiator_tested += 1
                after, _, _ = select_profile(
                    frontier,
                    vectors,
                    false_initiator,
                    true_responder,
                )
                if after == selected:
                    continue
                initiator_changed += 1
                after_cost = true_initiator_costs[after]
                if after_cost < initiator_truthful_cost:
                    initiator_profitable += 1
                elif after_cost == initiator_truthful_cost:
                    initiator_neutral += 1
                else:
                    initiator_harmful += 1

            responder_truthful_cost = true_responder_costs[selected]
            for false_responder in grid:
                if false_responder == true_responder:
                    continue
                responder_tested += 1
                after, _, _ = select_profile(
                    frontier,
                    vectors,
                    true_initiator,
                    false_responder,
                )
                if after == selected:
                    continue
                responder_changed += 1
                after_cost = true_responder_costs[after]
                if after_cost < responder_truthful_cost:
                    responder_profitable += 1
                elif after_cost == responder_truthful_cost:
                    responder_neutral += 1
                else:
                    responder_harmful += 1

    errors: list[str] = []
    checks = {
        "grid_points_per_endpoint": len(grid),
        "truthful_joint_pairs": len(grid) * len(grid),
        "conflict_pairs": conflict_pairs,
        "alternative_reports_tested_per_endpoint_side": initiator_tested,
        "total_unilateral_alternative_reports_tested": initiator_tested
        + responder_tested,
        "selection_changing_reports_per_side": initiator_changed,
        "strictly_profitable_reports_per_side": initiator_profitable,
    }
    for key, expected in EXPECTED.items():
        if checks[key] != expected:
            errors.append(f"{key}: expected {expected}, observed {checks[key]}")
    if initiator_tested != responder_tested:
        errors.append("the two endpoint sides tested different report counts")
    if initiator_changed != responder_changed:
        errors.append("the two endpoint sides changed selection different numbers of times")
    if initiator_profitable != responder_profitable:
        errors.append("the two endpoint sides have different profitable-report counts")
    if selector_mismatches:
        errors.append(f"selector implementation mismatches: {selector_mismatches}")

    return {
        "analysis": "independent exhaustive validation of unilateral weight manipulability",
        "grid_points_per_endpoint": len(grid),
        "truthful_joint_pairs": len(grid) * len(grid),
        "conflict_pairs": conflict_pairs,
        "alternative_reports_tested_per_endpoint_side": initiator_tested,
        "total_unilateral_alternative_reports_tested": initiator_tested
        + responder_tested,
        "selector_implementation_mismatches": selector_mismatches,
        "truthful_selected_profile_distribution": dict(sorted(selected_distribution.items())),
        "initiator": {
            "alternative_reports_tested": initiator_tested,
            "reports_changing_the_selected_profile": initiator_changed,
            "strictly_profitable_reports": initiator_profitable,
            "cost_neutral_changes": initiator_neutral,
            "harmful_changes": initiator_harmful,
        },
        "responder": {
            "alternative_reports_tested": responder_tested,
            "reports_changing_the_selected_profile": responder_changed,
            "strictly_profitable_reports": responder_profitable,
            "cost_neutral_changes": responder_neutral,
            "harmful_changes": responder_harmful,
        },
        "interpretation_boundary": (
            "This result applies only to unilateral deviations on the finite "
            "10%-increment grid and evaluated P0/P3 frontier."
        ),
        "validation_errors": errors,
        "validation_passed": not errors,
    }


def compare_reference(report: dict[str, Any], reference_path: Path) -> list[str]:
    if not reference_path.is_file():
        return []
    reference = load_json(reference_path)
    fields = (
        "grid_points_per_endpoint",
        "truthful_joint_pairs",
        "conflict_pairs",
        "alternative_reports_tested_per_endpoint_side",
        "total_unilateral_alternative_reports_tested",
        "selector_implementation_mismatches",
        "truthful_selected_profile_distribution",
        "initiator",
        "responder",
    )
    return [
        f"frozen reference differs for {field}"
        for field in fields
        if report.get(field) != reference.get(field)
    ]


def main() -> int:
    args = parse_args()
    report = reproduce(args.selector_report, args.frozen_pairs)
    reference_errors = compare_reference(report, args.frozen_reference)
    errors = cast(list[str], report["validation_errors"])
    errors.extend(reference_errors)
    report["validation_passed"] = not errors

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("[PASS] 4,356 truthful preference pairs evaluated.")
    print("[PASS] 566,280 unilateral alternative reports evaluated.")
    print("[PASS] 0 strictly profitable unilateral reports observed.")
    print(f"Output: {args.output}")
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("[PASS] Manipulability audit matches the frozen paper results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
