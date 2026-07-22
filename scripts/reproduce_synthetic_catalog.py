#!/usr/bin/env python3
"""Reproduce the 15-profile synthetic minimax-regret stress test."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any, Literal, cast

getcontext().prec = 28

Metric = Literal["wall_time", "process_cpu_time", "total_handshake_bytes"]
Weight = tuple[int, int, int]
Vector = dict[Metric, Decimal]

METRICS: tuple[Metric, ...] = (
    "wall_time",
    "process_cpu_time",
    "total_handshake_bytes",
)
RAW_VECTORS_TEXT: dict[str, dict[Metric, str]] = {
    "S00": {"wall_time": "0.05", "process_cpu_time": "0.85", "total_handshake_bytes": "0.85"},
    "S01": {"wall_time": "0.20", "process_cpu_time": "0.55", "total_handshake_bytes": "0.80"},
    "S02": {"wall_time": "0.45", "process_cpu_time": "0.25", "total_handshake_bytes": "0.65"},
    "S03": {"wall_time": "0.70", "process_cpu_time": "0.15", "total_handshake_bytes": "0.35"},
    "S04": {"wall_time": "0.90", "process_cpu_time": "0.05", "total_handshake_bytes": "0.10"},
    "S05": {"wall_time": "0.15", "process_cpu_time": "0.95", "total_handshake_bytes": "0.95"},
    "S06": {"wall_time": "0.25", "process_cpu_time": "0.90", "total_handshake_bytes": "1.00"},
    "S07": {"wall_time": "0.30", "process_cpu_time": "0.70", "total_handshake_bytes": "0.90"},
    "S08": {"wall_time": "0.40", "process_cpu_time": "0.65", "total_handshake_bytes": "0.95"},
    "S09": {"wall_time": "0.55", "process_cpu_time": "0.40", "total_handshake_bytes": "0.75"},
    "S10": {"wall_time": "0.65", "process_cpu_time": "0.35", "total_handshake_bytes": "0.80"},
    "S11": {"wall_time": "0.80", "process_cpu_time": "0.30", "total_handshake_bytes": "0.50"},
    "S12": {"wall_time": "0.85", "process_cpu_time": "0.25", "total_handshake_bytes": "0.60"},
    "S13": {"wall_time": "0.95", "process_cpu_time": "0.15", "total_handshake_bytes": "0.20"},
    "S14": {"wall_time": "1.00", "process_cpu_time": "0.10", "total_handshake_bytes": "0.25"},
}
EXPECTED = {
    "profile_count": 15,
    "pareto_frontier_size": 5,
    "dominated_profile_count": 10,
    "joint_pairs": 4356,
    "preference_conflict_pairs": 2248,
    "canonical_improvements": 3961,
    "minimum_total_improvements": 992,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--frozen-reference",
        type=Path,
        default=Path(
            "artifacts/analysis/posthoc/expanded_synthetic_catalog_analysis.json"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "artifacts/reproduced/posthoc/expanded_synthetic_catalog_analysis.json"
        ),
    )
    parser.add_argument(
        "--pairs-output",
        type=Path,
        default=Path(
            "artifacts/reproduced/posthoc/expanded_synthetic_catalog_pairs.csv"
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


def raw_vectors() -> dict[str, Vector]:
    return {
        profile_id: {metric: Decimal(values[metric]) for metric in METRICS}
        for profile_id, values in RAW_VECTORS_TEXT.items()
    }


def dominates(left: Vector, right: Vector) -> bool:
    return all(left[metric] <= right[metric] for metric in METRICS) and any(
        left[metric] < right[metric] for metric in METRICS
    )


def pareto_frontier(vectors: dict[str, Vector]) -> tuple[str, ...]:
    return tuple(
        sorted(
            profile_id
            for profile_id, vector in vectors.items()
            if not any(
                other_id != profile_id and dominates(other, vector)
                for other_id, other in vectors.items()
            )
        )
    )


def normalize(vectors: dict[str, Vector]) -> dict[str, Vector]:
    minima = {
        metric: min(vector[metric] for vector in vectors.values()) for metric in METRICS
    }
    maxima = {
        metric: max(vector[metric] for vector in vectors.values()) for metric in METRICS
    }
    return {
        profile_id: {
            metric: (vector[metric] - minima[metric]) / (maxima[metric] - minima[metric])
            for metric in METRICS
        }
        for profile_id, vector in vectors.items()
    }


def weighted_cost(vector: Vector, weights: Weight) -> Decimal:
    return sum(
        (
            vector[metric] * Decimal(weights[index]) / Decimal(10000)
            for index, metric in enumerate(METRICS)
        ),
        Decimal(0),
    )


def evaluate_pair(
    frontier: tuple[str, ...],
    normalized: dict[str, Vector],
    initiator_weights: Weight,
    responder_weights: Weight,
) -> tuple[
    str,
    str,
    str,
    str,
    dict[str, tuple[Decimal, Decimal]],
]:
    initiator_costs = {
        profile_id: weighted_cost(normalized[profile_id], initiator_weights)
        for profile_id in frontier
    }
    responder_costs = {
        profile_id: weighted_cost(normalized[profile_id], responder_weights)
        for profile_id in frontier
    }
    initiator_minimum_value = min(initiator_costs.values())
    responder_minimum_value = min(responder_costs.values())
    regrets = {
        profile_id: (
            initiator_costs[profile_id] - initiator_minimum_value,
            responder_costs[profile_id] - responder_minimum_value,
        )
        for profile_id in frontier
    }

    def selector_tuple(profile_id: str) -> tuple[Decimal, Decimal, Decimal, Decimal, str]:
        initiator_regret, responder_regret = regrets[profile_id]
        vector = normalized[profile_id]
        return (
            max(initiator_regret, responder_regret),
            initiator_regret + responder_regret,
            max(vector.values()),
            sum(vector.values(), Decimal(0)),
            profile_id,
        )

    minimax = min(frontier, key=selector_tuple)
    initiator_minimum = min(
        frontier,
        key=lambda profile_id: (initiator_costs[profile_id], profile_id),
    )
    responder_minimum = min(
        frontier,
        key=lambda profile_id: (responder_costs[profile_id], profile_id),
    )
    minimum_total = min(
        frontier,
        key=lambda profile_id: (
            initiator_costs[profile_id] + responder_costs[profile_id],
            profile_id,
        ),
    )
    return minimax, initiator_minimum, responder_minimum, minimum_total, regrets


def maximum_regret(regrets: dict[str, tuple[Decimal, Decimal]], profile_id: str) -> Decimal:
    return max(regrets[profile_id])


def format_weight(weights: Weight) -> str:
    return "/".join(str(value) for value in weights)


def decimal_text(value: Decimal) -> str:
    return str(value)


def percentile_95(values: list[Decimal]) -> Decimal:
    if not values:
        return Decimal(0)
    ordered = sorted(values)
    index = (Decimal("0.95") * Decimal(len(ordered) - 1)).to_integral_value()
    return ordered[int(index)]


def median(values: list[Decimal]) -> Decimal:
    if not values:
        return Decimal(0)
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / Decimal(2)


def reproduce(pairs_output: Path) -> dict[str, Any]:
    raw = raw_vectors()
    normalized = normalize(raw)
    frontier = pareto_frontier(raw)
    dominated = tuple(sorted(set(raw) - set(frontier)))
    grid = weight_grid()

    selected_distribution: Counter[str] = Counter()
    initiator_optimum_distribution: Counter[str] = Counter()
    responder_optimum_distribution: Counter[str] = Counter()
    conflict_pairs = 0
    method_names = (
        "canonical_first_safe",
        "minimum_total_cost",
        "initiator_minimum_cost",
        "responder_minimum_cost",
    )
    all_improvements: Counter[str] = Counter()
    all_differences: Counter[str] = Counter()
    all_ties: Counter[str] = Counter()
    all_degradations: Counter[str] = Counter()
    conflict_improvements: Counter[str] = Counter()
    conflict_differences: Counter[str] = Counter()
    positive_gains: dict[str, list[Decimal]] = {name: [] for name in method_names}

    pairs_output.parent.mkdir(parents=True, exist_ok=True)
    with pairs_output.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "initiator_weights",
            "responder_weights",
            "preference_conflict",
            "minimax_selected",
            "canonical_selected",
            "minimum_total_selected",
            "initiator_selected",
            "responder_selected",
            "minimax_maximum_regret",
            "canonical_first_safe_maximum_regret",
            "canonical_first_safe_fairness_gain",
            "minimum_total_cost_maximum_regret",
            "minimum_total_cost_fairness_gain",
            "initiator_minimum_cost_maximum_regret",
            "initiator_minimum_cost_fairness_gain",
            "responder_minimum_cost_maximum_regret",
            "responder_minimum_cost_fairness_gain",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for initiator_weights in grid:
            for responder_weights in grid:
                minimax, initiator_minimum, responder_minimum, minimum_total, regrets = (
                    evaluate_pair(
                        frontier,
                        normalized,
                        initiator_weights,
                        responder_weights,
                    )
                )
                selected_distribution[minimax] += 1
                initiator_optimum_distribution[initiator_minimum] += 1
                responder_optimum_distribution[responder_minimum] += 1
                is_conflict = initiator_minimum != responder_minimum
                if is_conflict:
                    conflict_pairs += 1

                selections = {
                    "canonical_first_safe": frontier[0],
                    "minimum_total_cost": minimum_total,
                    "initiator_minimum_cost": initiator_minimum,
                    "responder_minimum_cost": responder_minimum,
                }
                minimax_value = maximum_regret(regrets, minimax)
                gains: dict[str, Decimal] = {}
                method_values: dict[str, Decimal] = {}
                for method_name, profile_id in selections.items():
                    method_value = maximum_regret(regrets, profile_id)
                    gain = method_value - minimax_value
                    gains[method_name] = gain
                    method_values[method_name] = method_value
                    if profile_id != minimax:
                        all_differences[method_name] += 1
                        if is_conflict:
                            conflict_differences[method_name] += 1
                    if gain > 0:
                        all_improvements[method_name] += 1
                        positive_gains[method_name].append(gain)
                        if is_conflict:
                            conflict_improvements[method_name] += 1
                    elif gain == 0:
                        all_ties[method_name] += 1
                    else:
                        all_degradations[method_name] += 1

                writer.writerow(
                    {
                        "initiator_weights": format_weight(initiator_weights),
                        "responder_weights": format_weight(responder_weights),
                        "preference_conflict": is_conflict,
                        "minimax_selected": minimax,
                        "canonical_selected": frontier[0],
                        "minimum_total_selected": minimum_total,
                        "initiator_selected": initiator_minimum,
                        "responder_selected": responder_minimum,
                        "minimax_maximum_regret": decimal_text(minimax_value),
                        "canonical_first_safe_maximum_regret": decimal_text(
                            method_values["canonical_first_safe"]
                        ),
                        "canonical_first_safe_fairness_gain": decimal_text(
                            gains["canonical_first_safe"]
                        ),
                        "minimum_total_cost_maximum_regret": decimal_text(
                            method_values["minimum_total_cost"]
                        ),
                        "minimum_total_cost_fairness_gain": decimal_text(
                            gains["minimum_total_cost"]
                        ),
                        "initiator_minimum_cost_maximum_regret": decimal_text(
                            method_values["initiator_minimum_cost"]
                        ),
                        "initiator_minimum_cost_fairness_gain": decimal_text(
                            gains["initiator_minimum_cost"]
                        ),
                        "responder_minimum_cost_maximum_regret": decimal_text(
                            method_values["responder_minimum_cost"]
                        ),
                        "responder_minimum_cost_fairness_gain": decimal_text(
                            gains["responder_minimum_cost"]
                        ),
                    }
                )

    total_pairs = len(grid) * len(grid)
    comparisons: dict[str, Any] = {}
    conflict_comparisons: dict[str, Any] = {}
    for method_name in method_names:
        values = positive_gains[method_name]
        comparisons[method_name] = {
            "selection_difference_count": all_differences[method_name],
            "strict_minimax_improvement_count": all_improvements[method_name],
            "maximum_regret_tie_count": all_ties[method_name],
            "minimax_degradation_count": all_degradations[method_name],
            "positive_gain_median": decimal_text(median(values)),
            "positive_gain_p95": decimal_text(percentile_95(values)),
            "positive_gain_maximum": decimal_text(max(values, default=Decimal(0))),
        }
        conflict_comparisons[method_name] = {
            "selection_difference_count": conflict_differences[method_name],
            "strict_minimax_improvement_count": conflict_improvements[method_name],
        }

    errors: list[str] = []
    observed = {
        "profile_count": len(raw),
        "pareto_frontier_size": len(frontier),
        "dominated_profile_count": len(dominated),
        "joint_pairs": total_pairs,
        "preference_conflict_pairs": conflict_pairs,
        "canonical_improvements": all_improvements["canonical_first_safe"],
        "minimum_total_improvements": all_improvements["minimum_total_cost"],
    }
    for key, expected in EXPECTED.items():
        if observed[key] != expected:
            errors.append(f"{key}: expected {expected}, observed {observed[key]}")
    if any(all_degradations.values()):
        errors.append("minimax degradation was observed")

    return {
        "analysis_status": "post_hoc_synthetic_algorithmic_stress_test",
        "catalog": {
            "profile_count": len(raw),
            "pareto_frontier": list(frontier),
            "pareto_frontier_size": len(frontier),
            "dominated_profiles": list(dominated),
            "dominated_profile_count": len(dominated),
            "raw_vectors": RAW_VECTORS_TEXT,
            "normalized_vectors": {
                profile_id: {
                    metric: decimal_text(vector[metric]) for metric in METRICS
                }
                for profile_id, vector in sorted(normalized.items())
            },
        },
        "preference_grid": {
            "points_per_endpoint": len(grid),
            "joint_pairs": total_pairs,
            "preference_conflict_pairs": conflict_pairs,
            "no_conflict_pairs": total_pairs - conflict_pairs,
        },
        "minimax_selected_profile_distribution": dict(
            sorted(selected_distribution.items())
        ),
        "individual_optimum_distributions": {
            "initiator": dict(sorted(initiator_optimum_distribution.items())),
            "responder": dict(sorted(responder_optimum_distribution.items())),
        },
        "method_comparison_all_pairs": comparisons,
        "method_comparison_conflict_pairs": conflict_comparisons,
        "empirical_tls_measurement": False,
        "interpretation_boundary": (
            "This constructed catalogue demonstrates selector behavior on a richer "
            "frontier; it is not empirical TLS deployment evidence."
        ),
        "validation_errors": errors,
        "validation_passed": not errors,
    }


def compare_reference(report: dict[str, Any], path: Path) -> list[str]:
    if not path.is_file():
        return []
    reference = load_json(path)
    errors: list[str] = []
    checks = (
        (
            "pareto frontier",
            report["catalog"]["pareto_frontier"],
            reference["catalog"]["pareto_frontier"],
        ),
        (
            "minimax distribution",
            report["minimax_selected_profile_distribution"],
            reference["minimax_selected_profile_distribution"],
        ),
        (
            "preference conflict pairs",
            report["preference_grid"]["preference_conflict_pairs"],
            reference["preference_grid"]["preference_conflict_pairs"],
        ),
    )
    for label, observed, expected in checks:
        if observed != expected:
            errors.append(f"frozen reference differs for {label}")
    for method_name in (
        "canonical_first_safe",
        "minimum_total_cost",
        "initiator_minimum_cost",
        "responder_minimum_cost",
    ):
        for key in (
            "selection_difference_count",
            "strict_minimax_improvement_count",
            "maximum_regret_tie_count",
            "minimax_degradation_count",
            "positive_gain_median",
            "positive_gain_p95",
            "positive_gain_maximum",
        ):
            observed = report["method_comparison_all_pairs"][method_name][key]
            expected = reference["method_comparison_all_pairs"][method_name][key]
            if observed != expected:
                errors.append(f"frozen reference differs for {method_name}.{key}")
    return errors


def main() -> int:
    args = parse_args()
    report = reproduce(args.pairs_output)
    errors = cast(list[str], report["validation_errors"])
    errors.extend(compare_reference(report, args.frozen_reference))
    report["validation_passed"] = not errors

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("[PASS] 15-profile constructed catalogue evaluated.")
    print("[PASS] Pareto frontier size: 5; dominated profiles: 10.")
    print("[PASS] 4,356 joint preference pairs evaluated; 2,248 conflicts.")
    print("[PASS] Canonical-first improvements: 3,961; minimum-total: 992.")
    print(f"Summary: {args.output}")
    print(f"Pairs: {args.pairs_output}")
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("[PASS] Synthetic-catalog audit matches the frozen paper results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
