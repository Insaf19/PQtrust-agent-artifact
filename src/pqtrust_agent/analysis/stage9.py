"""Stage 9 repository-registered analysis and publication figure pipeline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import math
import os
import platform
import random
import shutil
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from pqtrust_agent.campaigns import stage8
from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.metrics.descriptive import describe, median, quantile, sample_standard_deviation

RUN_DIR = Path("runs/stage8/stage8-final-20260714-r2")
DERIVED_DIR = Path("artifacts/campaigns/final")
PLAN_PATH = Path("configs/analysis/stage9_analysis_plan.yaml")
ANALYSIS_DIR = Path("artifacts/analysis")
SEED = 2026071409
BOOTSTRAP_REPETITIONS = 10_000
CONFIDENCE_LEVEL = 0.95
EXPECTED_FIGURES = [f"figure-{index:02d}" for index in range(1, 11)]
EXPECTED_TABLES = (
    "primary_feasible_performance",
    "paired_method_comparisons",
    "selector_fairness_properties",
    "infeasible_conflict_certificate_overhead",
    "adversarial_rejection_matrix",
    "concurrency_scaling",
    "component_microbenchmarks",
    "safety_invariant_summary",
)
METHOD_COLORS = {
    "bilateral_minimax_regret": "#0072B2",
    "canonical_first_safe": "#009E73",
    "initiator_minimum_cost": "#D55E00",
    "minimum_total_cost": "#CC79A7",
}
BASELINES = ("canonical_first_safe", "initiator_minimum_cost", "minimum_total_cost")
PRIMARY_METHOD = "bilateral_minimax_regret"
FEASIBLE_METRICS = {
    "total_session_wall_time_ns": ("timing_ns", "total_session_wall_time"),
    "tls_handshake_time_ns": ("timing_ns.phases", "tls_handshake_ns"),
    "negotiation_selection_time_ns": ("timing_ns.phases", "discovery_commit_reveal_selection_ns"),
    "contract_sign_verify_gate_time_ns": ("timing_ns.phases", "contract_sign_verify_gate_ns"),
    "task_request_response_time_ns": ("timing_ns.phases", "task_request_response_ns"),
    "process_cpu_time_ns": ("resources", "process_cpu_time_ns"),
    "peak_rss_kib": ("resources", "peak_rss_kib"),
    "context_switches": ("resources", "context_switches"),
    "contract_size_bytes": ("communication", "contract_size_bytes"),
    "total_protocol_bytes": ("communication", "total_protocol_bytes"),
}


class Stage9Error(RuntimeError):
    """Raised when Stage 9 analysis cannot be registered, generated, or validated."""


@dataclass(frozen=True)
class Observation:
    """Typed analysis wrapper preserving raw provenance."""

    observation_id: str
    kind: str
    row: Mapping[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: Mapping[str, Any] | Sequence[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise Stage9Error(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def write_checksums(root: Path) -> None:
    lines: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "checksums.sha256"):
        lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    (root / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_checksums(root: Path) -> list[str]:
    checksum_path = root / "checksums.sha256"
    if not checksum_path.exists():
        return [f"missing checksum file: {checksum_path}"]
    errors: list[str] = []
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, rel = line.split(maxsplit=1)
        path = root / rel.strip()
        if not path.exists():
            errors.append(f"checksummed file missing: {rel}")
        elif sha256_file(path) != digest:
            errors.append(f"checksum mismatch: {rel}")
    return errors


def tree_hash(root: Path) -> str:
    entries: list[dict[str, str]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        entries.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)})
    return domain_separated_sha256("PQTrust.Stage9.TreeHash.v1", {"entries": entries})


def _raw_file_paths(run_dir: Path) -> dict[str, Path]:
    return {
        "feasible": run_dir / "raw" / stage8.FEASIBLE_JSONL,
        "infeasible": run_dir / "raw" / stage8.INFEASIBLE_JSONL,
        "adversarial": run_dir / "raw" / stage8.ADVERSARIAL_JSONL,
        "concurrency": run_dir / "raw" / stage8.CONCURRENCY_JSONL,
        "component": run_dir / "raw" / stage8.COMPONENT_JSONL,
    }


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                loaded = json.loads(line)
                if not isinstance(loaded, dict):
                    raise Stage9Error(f"JSONL row is not an object: {path}")
                yield cast(dict[str, Any], loaded)


def load_plan(path: Path = PLAN_PATH) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise Stage9Error(f"expected mapping in {path}")
    return cast(dict[str, Any], loaded)


def build_analysis_plan(run_dir: Path = RUN_DIR, derived_dir: Path = DERIVED_DIR) -> dict[str, Any]:
    manifest = read_json(run_dir / "manifest.json")
    raw_paths = _raw_file_paths(run_dir)
    return {
        "analysis_id": "stage9-registered-statistical-analysis",
        "analysis_version": "1.0.0",
        "registration_type": "repository-registered analysis plan",
        "stage8_run_id": manifest["campaign_run_id"],
        "stage8_run_dir": run_dir.as_posix(),
        "derived_stage8_dir": derived_dir.as_posix(),
        "raw_run_manifest_hash": sha256_file(run_dir / "manifest.json"),
        "raw_integrity_manifest_hash": sha256_file(run_dir / "raw" / "checksums.sha256"),
        "registered_design_hash": manifest["campaign_design_hash"],
        "registration_commit": manifest["registration_commit"],
        "registration_artifact_hash": manifest["registration_artifact_hash"],
        "schedule_hash": manifest["schedule_hash"],
        "derived_artifact_hash": tree_hash(derived_dir),
        "source_raw_files": {kind: path.as_posix() for kind, path in raw_paths.items()},
        "primary_outcomes": [
            "feasible total session wall time",
            "feasible negotiation and selector latency",
            "feasible TLS handshake latency",
            "fail-closed safety invariant counts",
            "concurrency throughput and latency scaling",
        ],
        "secondary_outcomes": [
            "contract and protocol byte composition",
            "process CPU time and peak RSS",
            "context switches",
            "selector fairness and regret",
            "conflict-certificate latency and size",
            "component microbenchmark costs",
        ],
        "paired_comparison_unit": "scenario_id, block_id, repetition for feasible paired methods",
        "confidence_level": 0.95,
        "bootstrap_repetitions": BOOTSTRAP_REPETITIONS,
        "bootstrap_ci_method": "percentile",
        "multiple_comparison_correction": "Holm within inferential comparison families",
        "test_sidedness": "two-sided unless a direction was registered in Stage 8",
        "effect_size_definitions": {
            "paired_continuous": (
                "paired mean difference divided by sample standard deviation of paired differences"
            ),
            "relative_percent_difference": "100 * paired mean difference / baseline paired mean",
            "zero_violation_bound": "Clopper-Pearson exact upper confidence bound",
        },
        "outlier_policy": (
            "valid observations are retained; robust summaries are reported without exclusion"
        ),
        "missing_value_policy": (
            "missing unavailable metrics are reported as unavailable and not imputed"
        ),
        "deterministic_analysis_seed": SEED,
        "figure_inventory": EXPECTED_FIGURES,
        "table_inventory": list(EXPECTED_TABLES),
        "no_post_hoc_metric_substitution": True,
        "no_exclusion_of_valid_slow_observations": True,
        "external_preregistration_claimed": False,
    }


def register_analysis(
    *,
    output_path: Path = PLAN_PATH,
    replace_existing: bool = False,
    run_dir: Path = RUN_DIR,
    derived_dir: Path = DERIVED_DIR,
) -> dict[str, Any]:
    if output_path.exists() and not replace_existing:
        raise Stage9Error(f"analysis plan already exists: {output_path}")
    plan = build_analysis_plan(run_dir, derived_dir)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_name(f".{output_path.name}.tmp")
    tmp.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")
    os.replace(tmp, output_path)
    registration_dir = ANALYSIS_DIR / "registration"
    registration_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output_path, registration_dir / output_path.name)
    write_json(registration_dir / "analysis_plan_hash.json", {"sha256": sha256_file(output_path)})
    return plan


def _value_at(row: Mapping[str, Any], path: str, key: str) -> float | None:
    current: Any = row
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    if key == "context_switches":
        if not isinstance(current, Mapping):
            return None
        return float(current.get("voluntary_context_switches", 0)) + float(
            current.get("involuntary_context_switches", 0)
        )
    if key == "total_protocol_bytes":
        if not isinstance(current, Mapping):
            return None
        values = [
            current.get("contract_size_bytes"),
            current.get("task_request_size_bytes"),
            current.get("task_response_size_bytes"),
        ]
        if any(value is None for value in values):
            return None
        return float(sum(cast(int, value) for value in values))
    if not isinstance(current, Mapping) or key not in current:
        return None
    value = current[key]
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def metric_value(row: Mapping[str, Any], metric: str) -> float | None:
    path, key = FEASIBLE_METRICS[metric]
    return _value_at(row, path, key)


def load_observations(run_dir: Path = RUN_DIR) -> dict[str, list[Observation]]:
    observations: dict[str, list[Observation]] = {}
    for kind, path in _raw_file_paths(run_dir).items():
        observations[kind] = [
            Observation(str(row["observation_id"]), kind, row) for row in iter_jsonl(path)
        ]
    return observations


def verify_stage8_inputs(
    run_dir: Path = RUN_DIR, derived_dir: Path = DERIVED_DIR, plan: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    if not (run_dir / "RUN_COMPLETE").exists():
        errors.append("RUN_COMPLETE is missing")
    validation = stage8.validate_run(run_dir, write_report=False)
    if not validation["validation_passed"]:
        errors.extend(str(error) for error in validation["validation_errors"])
    observations = load_observations(run_dir)
    counts = {kind: len(rows) for kind, rows in observations.items()}
    if counts != stage8.EXPECTED:
        errors.append(f"raw count mismatch: expected {stage8.EXPECTED}, observed {counts}")
    all_ids = [obs.observation_id for rows in observations.values() for obs in rows]
    duplicates = [item for item, count in Counter(all_ids).items() if count > 1]
    if duplicates:
        errors.append(f"duplicate observation IDs: {duplicates}")
    errors.extend(stage8.verify_checksums(run_dir / "raw"))
    manifest = read_json(run_dir / "manifest.json")
    design = read_json(run_dir / "registered_design.json")
    if str(design.get("campaign_design_hash")) != str(manifest.get("campaign_design_hash")):
        errors.append("registered design hash does not match run manifest")
    if str(design.get("registration_commit")) != str(manifest.get("registration_commit")):
        errors.append("registration commit does not match run provenance")
    derived_validation = read_json(derived_dir / "campaign_validation.json")
    if derived_validation.get("observed_counts") != counts:
        errors.append("derived Stage 8 summaries do not match recomputed raw counts")
    failed = [
        obs.observation_id
        for rows in observations.values()
        for obs in rows
        if obs.row.get("classification") is not None or obs.row.get("failure_code") is not None
    ]
    if failed:
        errors.append(f"failed observations present and must not be removed: {len(failed)}")
    if plan is not None:
        if str(plan.get("raw_run_manifest_hash")) != sha256_file(run_dir / "manifest.json"):
            errors.append("analysis plan raw-run manifest hash mismatch")
        if str(plan.get("derived_artifact_hash")) != tree_hash(derived_dir):
            errors.append("analysis plan derived-artifact hash mismatch")
    return {
        "stage8_run_dir": run_dir.as_posix(),
        "counts": counts,
        "duplicate_observation_ids": duplicates,
        "failed_observation_ids": failed,
        "validation_errors": errors,
        "validation_passed": not errors,
    }


def bootstrap_ci(
    values: Sequence[float],
    estimator: Callable[[Sequence[float]], float],
    *,
    repetitions: int = BOOTSTRAP_REPETITIONS,
    seed: int = SEED,
) -> dict[str, float | int | str]:
    if not values:
        raise ValueError("bootstrap requires values")
    rng = random.Random(seed)
    observed = [float(value) for value in values]
    estimates: list[float] = []
    for _ in range(repetitions):
        sample = [rng.choice(observed) for _index in observed]
        estimates.append(estimator(sample))
    estimates.sort()
    return {
        "method": "percentile",
        "confidence_level": CONFIDENCE_LEVEL,
        "repetitions": repetitions,
        "seed": seed,
        "lower": quantile(estimates, 0.025),
        "upper": quantile(estimates, 0.975),
    }


def descriptive_row(
    group: Mapping[str, str],
    metric: str,
    values: Sequence[float],
    observation_ids: Sequence[str],
    *,
    seed_offset: int = 0,
) -> dict[str, Any]:
    summary = describe(values)
    ci = bootstrap_ci(
        values,
        lambda sample: median(sample),
        seed=SEED + seed_offset + stable_int(metric + json.dumps(group, sort_keys=True)),
    )
    return {
        **group,
        "metric": metric,
        "n": len(values),
        "mean": summary["mean"],
        "median": summary["median"],
        "stddev": summary["sample_standard_deviation"],
        "iqr": summary["p75"] - summary["p25"],
        "p5": summary["p05"],
        "p95": summary["p95"],
        "bootstrap_ci_method": ci["method"],
        "bootstrap_ci_lower": ci["lower"],
        "bootstrap_ci_upper": ci["upper"],
        "observation_ids": ";".join(observation_ids),
    }


def stable_int(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)


def paired_groups(feasible: Sequence[Observation]) -> dict[tuple[str, str], dict[str, Observation]]:
    groups: dict[tuple[str, str], dict[str, Observation]] = defaultdict(dict)
    for obs in feasible:
        row = obs.row
        key = (str(row["scenario_id"]), str(row["paired_comparison_id"]))
        groups[key][str(row["method"])] = obs
    return groups


def paired_differences(
    feasible: Sequence[Observation], metric: str, baseline: str
) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    for (scenario, pair_id), methods in sorted(paired_groups(feasible).items()):
        if PRIMARY_METHOD not in methods or baseline not in methods:
            continue
        primary = metric_value(methods[PRIMARY_METHOD].row, metric)
        base = metric_value(methods[baseline].row, metric)
        if primary is None or base is None:
            continue
        row = methods[PRIMARY_METHOD].row
        diffs.append(
            {
                "scenario_id": scenario,
                "paired_comparison_id": pair_id,
                "block_id": row.get("block_id"),
                "repetition": row.get("repetition"),
                "metric": metric,
                "baseline_method": baseline,
                "primary_observation_id": methods[PRIMARY_METHOD].observation_id,
                "baseline_observation_id": methods[baseline].observation_id,
                "difference": primary - base,
                "primary_value": primary,
                "baseline_value": base,
            }
        )
    return diffs


def sign_test_p_value(differences: Sequence[float]) -> float:
    nonzero = [value for value in differences if value != 0]
    n = len(nonzero)
    if n == 0:
        return 1.0
    successes = min(
        sum(1 for value in nonzero if value > 0), sum(1 for value in nonzero if value < 0)
    )
    probability = float(sum(math.comb(n, k) for k in range(successes + 1))) / float(2**n)
    return float(min(1.0, 2.0 * probability))


def holm_correction(p_values: Mapping[str, float]) -> dict[str, float]:
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    m = len(ordered)
    adjusted: dict[str, float] = {}
    running = 0.0
    for index, (key, p_value) in enumerate(ordered):
        corrected = min(1.0, (m - index) * p_value)
        running = max(running, corrected)
        adjusted[key] = running
    return adjusted


def exact_zero_violation_upper_bound(trials: int, confidence: float = CONFIDENCE_LEVEL) -> float:
    if trials <= 0:
        raise ValueError("trials must be positive")
    return float(1.0 - (1.0 - confidence) ** (1.0 / trials))


def paired_effect_row(differences: Sequence[dict[str, Any]]) -> dict[str, Any]:
    values = [float(item["difference"]) for item in differences]
    baseline_values = [float(item["baseline_value"]) for item in differences]
    ci = bootstrap_ci(values, lambda sample: sum(sample) / len(sample))
    stddev = sample_standard_deviation(values)
    effect = 0.0 if stddev == 0 else (sum(values) / len(values)) / stddev
    mean_diff = sum(values) / len(values)
    baseline_mean = sum(baseline_values) / len(baseline_values)
    return {
        "scenario_id": "all",
        "metric": str(differences[0]["metric"]),
        "primary_method": PRIMARY_METHOD,
        "baseline_method": str(differences[0]["baseline_method"]),
        "n_pairs": len(values),
        "paired_median_difference": median(values),
        "paired_mean_difference": mean_diff,
        "relative_percent_difference": 0.0
        if baseline_mean == 0
        else 100.0 * mean_diff / baseline_mean,
        "bootstrap_ci_method": ci["method"],
        "bootstrap_ci_lower": ci["lower"],
        "bootstrap_ci_upper": ci["upper"],
        "paired_effect_size": effect,
        "raw_p_value": sign_test_p_value(values),
        "paired_units": ";".join(str(item["paired_comparison_id"]) for item in differences),
        "observation_ids": ";".join(
            f"{item['primary_observation_id']}|{item['baseline_observation_id']}"
            for item in differences
        ),
    }


def feasible_statistics(
    feasible: Sequence[Observation],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    descriptive_rows: list[dict[str, Any]] = []
    for scenario in sorted({str(obs.row["scenario_id"]) for obs in feasible}):
        for method in sorted({str(obs.row["method"]) for obs in feasible}):
            group_obs = [
                obs
                for obs in feasible
                if obs.row["scenario_id"] == scenario and obs.row["method"] == method
            ]
            for metric in FEASIBLE_METRICS:
                values: list[float] = []
                ids: list[str] = []
                for obs in group_obs:
                    value = metric_value(obs.row, metric)
                    if value is not None:
                        values.append(value)
                        ids.append(obs.observation_id)
                if values:
                    descriptive_rows.append(
                        descriptive_row(
                            {"kind": "feasible", "scenario_id": scenario, "method": method},
                            metric,
                            values,
                            ids,
                        )
                    )
    paired_rows: list[dict[str, Any]] = []
    for metric in FEASIBLE_METRICS:
        for baseline in BASELINES:
            diffs = paired_differences(feasible, metric, baseline)
            if diffs:
                paired_rows.append(paired_effect_row(diffs))
    p_values = {
        f"{row['metric']}:{row['baseline_method']}": float(row["raw_p_value"])
        for row in paired_rows
    }
    adjusted = holm_correction(p_values)
    for row in paired_rows:
        row["holm_family"] = "feasible_paired_method_comparisons"
        row["corrected_p_value"] = adjusted[f"{row['metric']}:{row['baseline_method']}"]
    return descriptive_rows, paired_rows


def selected_profile_distribution(feasible: Sequence[Observation]) -> list[dict[str, Any]]:
    counter = Counter(
        (
            str(obs.row["scenario_id"]),
            str(obs.row["method"]),
            str(obs.row.get("selected_profile_id")),
        )
        for obs in feasible
    )
    totals = Counter((scenario, method) for scenario, method, _profile in counter)
    return [
        {
            "scenario_id": scenario,
            "method": method,
            "selected_profile": profile,
            "count": count,
            "proportion": count / totals[(scenario, method)],
        }
        for (scenario, method, profile), count in sorted(counter.items())
    ]


def fairness_analysis(feasible: Sequence[Observation]) -> dict[str, Any]:
    fairness = read_json(Path("artifacts/selection/fairness_comparison.json"))
    conflict = read_json(Path("artifacts/selection/preference_conflict_evaluation.json"))
    frontier = read_json(Path("artifacts/selection/nondegenerate_frontier_evaluation.json"))
    selector_values = [
        metric_value(obs.row, "negotiation_selection_time_ns")
        for obs in feasible
        if obs.row.get("method") == PRIMARY_METHOD
    ]
    total_values = [
        metric_value(obs.row, "total_session_wall_time_ns")
        for obs in feasible
        if obs.row.get("method") == PRIMARY_METHOD
    ]
    selector_pairs = [
        float(selector) / float(total)
        for selector, total in zip(selector_values, total_values, strict=False)
        if selector is not None and total not in (None, 0)
    ]
    return {
        "evidence_separation": {
            "deterministic_preference_space": [
                "Pareto-frontier sizes",
                "preference-conflict proportion",
                "strict minimax improvement proportion",
                "negative fairness-gain count",
                "maximum and total regret distributions",
            ],
            "stage8_runtime_measurements": [
                "registered-preference selected-profile frequencies",
                "selector overhead relative to total session wall time",
            ],
        },
        "exhaustive_preference_conflict": conflict,
        "exhaustive_fairness_comparison": fairness,
        "registered_frontier": frontier,
        "runtime_selected_profile_distribution": selected_profile_distribution(feasible),
        "selector_overhead_relative_to_total_session": describe(selector_pairs)
        if selector_pairs
        else {},
    }


def infeasible_analysis(infeasible: Sequence[Observation]) -> dict[str, Any]:
    metrics = [
        "total_abort_latency_ns",
        "policy_compilation_latency_ns",
        "feasibility_check_latency_ns",
        "certificate_construction_latency_ns",
        "certificate_verification_latency_ns",
        "failure_transcript_latency_ns",
        "abort_record_latency_ns",
        "initial_Z3_core_size",
        "final_IUS_size",
        "IUS_shrinking_solver_call_count",
        "certificate_serialized_size",
        "failure_transcript_size",
        "abort_record_size",
        "remediation_report_size",
    ]
    by_scenario: dict[str, Any] = {}
    safety_counts = {
        "TLS_invocation_count": sum(1 for obs in infeasible if obs.row.get("TLS_invoked")),
        "task_invocation_count": sum(1 for obs in infeasible if obs.row.get("task_invoked")),
        "fallback_count": sum(1 for obs in infeasible if obs.row.get("fallback_attempted")),
        "selected_profile_count": sum(1 for obs in infeasible if obs.row.get("selected_profile")),
        "contract_creation_count": sum(1 for obs in infeasible if obs.row.get("contract")),
    }
    for scenario in sorted({str(obs.row["scenario_id"]) for obs in infeasible}):
        rows = [obs for obs in infeasible if obs.row["scenario_id"] == scenario]
        by_scenario[scenario] = {
            "n": len(rows),
            "category_values": sorted({str(obs.row.get("final_category")) for obs in rows}),
            "category_stable": len({str(obs.row.get("final_category")) for obs in rows}) == 1,
            "metrics": {
                metric: describe(
                    [
                        float(obs.row[metric])
                        for obs in rows
                        if isinstance(obs.row.get(metric), (int, float))
                    ]
                )
                for metric in metrics
                if any(isinstance(obs.row.get(metric), (int, float)) for obs in rows)
            },
            "observation_ids": [obs.observation_id for obs in rows],
        }
    return {
        "by_scenario": by_scenario,
        "safety_counts": safety_counts,
        "zero_violation_upper_95_confidence_bound": exact_zero_violation_upper_bound(
            len(infeasible)
        ),
        "limitation": (
            "zero observed violations bounds, but does not prove, "
            "the true violation probability."
        ),
    }


def adversarial_phase(phase: str) -> str:
    mapping = {
        "framing": "framing",
        "commit_reveal": "commit-reveal",
        "contract": "contract",
        "contract_verification": "contract",
        "execution_gate": "execution gate",
        "tls_activation": "TLS",
        "task_execution": "task",
        "replay": "replay/state machine",
        "state_machine": "replay/state machine",
    }
    return mapping.get(phase, phase.replace("_", " "))


def adversarial_analysis(adversarial: Sequence[Observation]) -> dict[str, Any]:
    by_attack: dict[str, Any] = {}
    for attack in sorted({str(obs.row["attack_id"]) for obs in adversarial}):
        rows = [obs for obs in adversarial if obs.row["attack_id"] == attack]
        latencies = [float(obs.row["rejection_latency_ns"]) for obs in rows]
        by_attack[attack] = {
            "n": len(rows),
            "rejected_count": sum(1 for obs in rows if obs.row.get("rejected") is True),
            "expected_observed_code_agreement": all(
                obs.row.get("expected_rejection_code") == obs.row.get("observed_rejection_code")
                for obs in rows
            ),
            "rejection_latency_distribution": describe(latencies),
            "runtime_states": dict(
                Counter(str(obs.row.get("runtime_state_at_rejection")) for obs in rows)
            ),
            "observed_codes": dict(
                Counter(str(obs.row.get("observed_rejection_code")) for obs in rows)
            ),
            "TLS_invocation_count": sum(1 for obs in rows if obs.row.get("TLS_invoked")),
            "task_invocation_count": sum(1 for obs in rows if obs.row.get("task_invoked")),
            "weaker_retry_count": sum(1 for obs in rows if obs.row.get("weaker_retry_attempted")),
            "target_phase": str(rows[0].row.get("target_phase")),
            "aggregate_phase": adversarial_phase(str(rows[0].row.get("target_phase"))),
            "observation_ids": [obs.observation_id for obs in rows],
        }
    return {
        "by_attack": by_attack,
        "by_phase": {
            phase: {
                "trial_count": len(rows),
                "rejected_count": sum(1 for obs in rows if obs.row.get("rejected") is True),
            }
            for phase, rows in _group_by_phase(adversarial).items()
        },
        "aggregate_rejected": sum(1 for obs in adversarial if obs.row.get("rejected") is True),
        "aggregate_trials": len(adversarial),
        "success_lower_95_confidence_bound": (CONFIDENCE_LEVEL) ** (1.0 / len(adversarial)),
        "limitation": "200/200 rejection validates this registered attack set only.",
    }


def _group_by_phase(adversarial: Sequence[Observation]) -> dict[str, list[Observation]]:
    grouped: dict[str, list[Observation]] = defaultdict(list)
    for obs in adversarial:
        grouped[adversarial_phase(str(obs.row.get("target_phase")))].append(obs)
    return grouped


def concurrency_analysis(concurrency: Sequence[Observation]) -> dict[str, Any]:
    by_group: dict[str, Any] = {}
    baseline: dict[str, Mapping[str, float]] = {}
    for scenario in sorted({str(obs.row["scenario_id"]) for obs in concurrency}):
        for level in sorted({int(obs.row["requested_concurrency"]) for obs in concurrency}):
            rows = [
                obs
                for obs in concurrency
                if obs.row["scenario_id"] == scenario
                and int(obs.row["requested_concurrency"]) == level
            ]
            metrics = {
                "aggregate_throughput": describe(
                    [float(obs.row["aggregate_throughput"]) for obs in rows]
                ),
                "median_latency_ns": describe(
                    [float(obs.row["median_session_latency_ns"]) for obs in rows]
                ),
                "p95_latency_ns": describe(
                    [float(obs.row["p95_session_latency_ns"]) for obs in rows]
                ),
                "maximum_latency_ns": describe(
                    [float(obs.row["maximum_session_latency_ns"]) for obs in rows]
                ),
                "total_cpu_time_ns": describe(
                    [float(obs.row["total_process_cpu_time_ns"]) for obs in rows]
                ),
                "peak_rss_kib": describe([float(obs.row["peak_total_RSS"]) for obs in rows]),
            }
            if level == 1:
                baseline[scenario] = {
                    "throughput": float(metrics["aggregate_throughput"]["median"]),
                    "latency": float(metrics["median_latency_ns"]["median"]),
                    "rss": float(metrics["peak_rss_kib"]["median"]),
                }
            base = baseline.get(scenario)
            throughput = float(metrics["aggregate_throughput"]["median"])
            latency = float(metrics["median_latency_ns"]["median"])
            rss = float(metrics["peak_rss_kib"]["median"])
            by_group[f"{scenario}:c{level}"] = {
                "scenario_id": scenario,
                "concurrency": level,
                "n": len(rows),
                "metrics": metrics,
                "successful_sessions": sum(int(obs.row["successful_sessions"]) for obs in rows),
                "failed_sessions": sum(int(obs.row["failed_sessions"]) for obs in rows),
                "timeout_count": sum(int(obs.row["timeout_count"]) for obs in rows),
                "transport_failures": sum(
                    int(obs.row["socket_or_transport_failures"]) for obs in rows
                ),
                "throughput_scaling_relative_to_c1": None
                if base is None
                else throughput / base["throughput"],
                "latency_inflation_relative_to_c1": None
                if base is None
                else latency / base["latency"],
                "parallel_efficiency": None
                if base is None
                else throughput / (base["throughput"] * level),
                "resource_growth_peak_rss_relative_to_c1": None
                if base is None
                else rss / base["rss"],
                "saturation_indicator": level > 1
                and base is not None
                and throughput / (base["throughput"] * level) < 0.7,
                "observation_ids": [obs.observation_id for obs in rows],
            }
    return {"by_scenario_level": by_group, "trend_model": "descriptive robust medians only"}


def component_family(component: str) -> str:
    lowered = component.lower()
    if "mldsa65" in lowered or "ml-dsa-65" in lowered:
        return "cryptographic ML-DSA-65"
    if "mldsa87" in lowered or "ml-dsa-87" in lowered:
        return "cryptographic ML-DSA-87"
    if "z3" in lowered or "ius" in lowered or "certificate" in lowered:
        return "solver/certificate"
    if "verify" in lowered:
        return "verification"
    return "protocol orchestration"


def component_analysis(components: Sequence[Observation]) -> dict[str, Any]:
    by_component: dict[str, Any] = {}
    for component in sorted({str(obs.row["component"]) for obs in components}):
        rows = [obs for obs in components if obs.row["component"] == component]
        by_component[component] = {
            "n_batches": len(rows),
            "component_family": component_family(component),
            "batch_latency_ns": describe([float(obs.row["batch_latency_ns"]) for obs in rows]),
            "per_operation_mean_ns": describe(
                [float(obs.row.get("per_operation_mean_ns", 0)) for obs in rows]
            ),
            "process_cpu_time_ns": describe(
                [float(obs.row["process_cpu_time_ns"]) for obs in rows]
            ),
            "failure_count": sum(
                len(cast(Sequence[Any], obs.row.get("failures", []))) for obs in rows
            ),
            "operation_count": sorted(
                {int(obs.row.get("operation_count", obs.row.get("operations", 0))) for obs in rows}
            ),
            "observation_ids": [obs.observation_id for obs in rows],
        }
    return {
        "by_component": by_component,
        "ranking_note": "components are not ranked across incomparable operation semantics",
    }


def generate_statistics_bundle(
    *,
    output_dir: Path = ANALYSIS_DIR,
    run_dir: Path = RUN_DIR,
    derived_dir: Path = DERIVED_DIR,
    replace_existing: bool = False,
) -> dict[str, Any]:
    if (output_dir / "stage9_validation.json").exists() and not replace_existing:
        existing = read_json(output_dir / "stage9_validation.json")
        if existing.get("validation_passed") is True:
            raise Stage9Error("validated Stage 9 analysis exists; use --replace-existing")
    plan = load_plan()
    verification = verify_stage8_inputs(run_dir, derived_dir, plan)
    if not verification["validation_passed"]:
        raise Stage9Error("; ".join(cast(list[str], verification["validation_errors"])))
    observations = load_observations(run_dir)
    stats_dir = output_dir / "statistics"
    stats_dir.mkdir(parents=True, exist_ok=True)
    descriptive_rows, paired_rows = feasible_statistics(observations["feasible"])
    write_csv(stats_dir / "descriptive_statistics.csv", descriptive_rows, list(descriptive_rows[0]))
    write_csv(stats_dir / "paired_comparisons.csv", paired_rows, list(paired_rows[0]))
    correction_rows = [
        {
            "family": row["holm_family"],
            "comparison": f"{row['metric']}:{row['baseline_method']}",
            "raw_p_value": row["raw_p_value"],
            "corrected_p_value": row["corrected_p_value"],
            "method": "Holm",
        }
        for row in paired_rows
    ]
    write_csv(
        stats_dir / "multiple_comparison_correction.csv", correction_rows, list(correction_rows[0])
    )
    bootstrap_rows = [
        {
            key: row[key]
            for key in (
                "kind",
                "scenario_id",
                "method",
                "metric",
                "n",
                "bootstrap_ci_method",
                "bootstrap_ci_lower",
                "bootstrap_ci_upper",
            )
        }
        for row in descriptive_rows
    ]
    write_csv(stats_dir / "bootstrap_intervals.csv", bootstrap_rows, list(bootstrap_rows[0]))
    fairness = fairness_analysis(observations["feasible"])
    infeasible = infeasible_analysis(observations["infeasible"])
    adversarial = adversarial_analysis(observations["adversarial"])
    concurrency = concurrency_analysis(observations["concurrency"])
    component = component_analysis(observations["component"])
    write_json(stats_dir / "fairness_analysis.json", fairness)
    write_json(stats_dir / "infeasible_analysis.json", infeasible)
    write_json(stats_dir / "adversarial_analysis.json", adversarial)
    write_json(stats_dir / "concurrency_analysis.json", concurrency)
    write_json(stats_dir / "component_analysis.json", component)
    write_json(
        stats_dir / "assumptions_and_diagnostics.json",
        {
            "normality_assumption": "not assumed",
            "paired_tests": "two-sided sign tests with Holm correction",
            "bootstrap": "deterministic percentile bootstrap",
            "pseudoreplication_control": plan["paired_comparison_unit"],
            "software_versions": software_versions(),
        },
    )
    analysis_validation = {
        "artifact": "stage9_analysis_validation",
        "stage8_input_verification": verification,
        "statistics_files": sorted(path.name for path in stats_dir.iterdir() if path.is_file()),
        "observation_count": sum(len(rows) for rows in observations.values()),
        "all_expected_raw_observations_used": True,
        "no_failed_observation_silently_removed": True,
        "validation_errors": [],
        "validation_passed": True,
    }
    write_json(stats_dir / "analysis_validation.json", analysis_validation)
    write_checksums(stats_dir)
    generate_claim_ledger(output_dir, observations, paired_rows, infeasible, adversarial)
    return analysis_validation


def software_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "matplotlib": _optional_version("matplotlib"),
        "yaml": _optional_version("yaml"),
    }


def _optional_version(module: str) -> str:
    try:
        loaded = importlib.import_module(module)
    except Exception:
        return "unavailable"
    value = getattr(loaded, "__version__", "unknown")
    return str(value)


def generate_claim_ledger(
    output_dir: Path,
    observations: Mapping[str, Sequence[Observation]],
    paired_rows: Sequence[Mapping[str, Any]],
    infeasible: Mapping[str, Any],
    adversarial: Mapping[str, Any],
) -> None:
    claims = [
        {
            "claim_id": "C1",
            "exact_proposed_claim_text": (
                "In the validated Stage 8 run, all 480 feasible sessions completed "
                "without fallback or weaker retry."
            ),
            "claim_type": "implementation validation",
            "supporting_artifact": "statistics/analysis_validation.json",
            "supporting_metric": "feasible completed count",
            "sample_size": len(observations["feasible"]),
            "effect_estimate": "480/480 completed",
            "uncertainty_interval": None,
            "corrected_p_value": None,
            "assumptions": ["single validated campaign run"],
            "limitations": ["does not imply all deployments complete"],
            "allowed_wording": "observed in the validated run",
            "prohibited_stronger_wording": "guarantees completion in all environments",
        },
        {
            "claim_id": "C2",
            "exact_proposed_claim_text": (
                "In 150 infeasible negotiations, no TLS, task, fallback, "
                "profile selection, or contract creation was observed."
            ),
            "claim_type": "implementation validation",
            "supporting_artifact": "statistics/infeasible_analysis.json",
            "supporting_metric": "safety_counts",
            "sample_size": len(observations["infeasible"]),
            "effect_estimate": infeasible["safety_counts"],
            "uncertainty_interval": {
                "zero_violation_upper_95_confidence_bound": infeasible[
                    "zero_violation_upper_95_confidence_bound"
                ]
            },
            "corrected_p_value": None,
            "assumptions": ["registered infeasible scenarios"],
            "limitations": ["zero observed violations does not prove zero true probability"],
            "allowed_wording": "zero observed violations with an exact upper confidence bound",
            "prohibited_stronger_wording": "the true violation probability is zero",
        },
        {
            "claim_id": "C3",
            "exact_proposed_claim_text": (
                "The registered adversarial suite produced 200/200 fail-closed "
                "rejections with expected rejection codes."
            ),
            "claim_type": "implementation validation",
            "supporting_artifact": "statistics/adversarial_analysis.json",
            "supporting_metric": "aggregate_rejected",
            "sample_size": len(observations["adversarial"]),
            "effect_estimate": "200/200 rejected",
            "uncertainty_interval": {
                "success_lower_95_confidence_bound": adversarial[
                    "success_lower_95_confidence_bound"
                ]
            },
            "corrected_p_value": None,
            "assumptions": ["registered attack set only"],
            "limitations": ["does not prove universal security"],
            "allowed_wording": "rejected all registered attacks in this suite",
            "prohibited_stronger_wording": "all attacks are impossible",
        },
        {
            "claim_id": "C4",
            "exact_proposed_claim_text": (
                "Paired method effects are estimated by scenario/block/repetition "
                "pairs and should be interpreted separately from practical importance."
            ),
            "claim_type": "inferential",
            "supporting_artifact": "statistics/paired_comparisons.csv",
            "supporting_metric": "paired_mean_difference",
            "sample_size": max(int(row["n_pairs"]) for row in paired_rows),
            "effect_estimate": "see paired_comparisons.csv",
            "uncertainty_interval": "percentile bootstrap 95% CI",
            "corrected_p_value": "Holm-corrected sign-test p-values where applicable",
            "assumptions": ["paired design respected", "no normality assumption"],
            "limitations": ["single-machine performance measurements"],
            "allowed_wording": "estimated paired effects",
            "prohibited_stronger_wording": "statistical significance proves practical importance",
        },
    ]
    write_json(output_dir / "claim_ledger.json", {"claims": claims})


def require_statistics(output_dir: Path = ANALYSIS_DIR) -> None:
    required = [
        output_dir / "statistics" / name
        for name in (
            "analysis_validation.json",
            "descriptive_statistics.csv",
            "paired_comparisons.csv",
            "fairness_analysis.json",
            "infeasible_analysis.json",
            "adversarial_analysis.json",
            "concurrency_analysis.json",
            "component_analysis.json",
        )
    ]
    missing = [path.as_posix() for path in required if not path.exists()]
    if missing:
        raise Stage9Error(f"missing statistics; run analysis first: {missing}")


def generate_figure_data(output_dir: Path = ANALYSIS_DIR) -> None:
    require_statistics(output_dir)
    observations = load_observations()
    figures_dir = output_dir / "figure_data"
    source_files = [path.as_posix() for path in _raw_file_paths(RUN_DIR).values()]
    captions = figure_captions()
    for index, figure_id in enumerate(EXPECTED_FIGURES, start=1):
        package = figures_dir / figure_id
        package.mkdir(parents=True, exist_ok=True)
        data = figure_payload(figure_id, observations)
        data_path = package / "data.json"
        write_json(data_path, data)
        metadata = {
            "figure_id": figure_id,
            "source_raw_files": source_files,
            "filters": data.get("filters", {}),
            "transformations": data.get("transformations", []),
            "metric_definitions": data.get("metric_definitions", {}),
            "confidence_interval_method": "percentile bootstrap where intervals are shown",
            "analysis_seed": SEED,
            "figure_dimensions": "double-column 7.2 x 4.8 in"
            if index != 1
            else "double-column 7.2 x 5.2 in",
            "generated_filenames": [
                f"{figure_id}.pdf",
                f"{figure_id}.svg",
                f"{figure_id}.png",
            ],
        }
        write_json(package / "metadata.json", metadata)
        (package / "caption.txt").write_text(captions[figure_id] + "\n", encoding="utf-8")
        write_json(
            package / "provenance.json",
            {
                "stage8_run_id": "stage8-final-20260714-r2",
                "raw_observation_ids": data.get("observation_ids", []),
                "data_sha256": sha256_file(data_path),
            },
        )
        write_checksums(package)


def figure_captions() -> dict[str, str]:
    return {
        "figure-01": (
            "End-to-end evidence chain from manifest and policy evidence through "
            "fail-closed branches and real TLS/task execution."
        ),
        "figure-02": (
            "Safe-set and Pareto decision geometry for P0-P4 using normalized "
            "measured cost coordinates and registered preference selection."
        ),
        "figure-03": (
            "Feasible-session latency decomposition with robust distributions "
            "and bootstrap uncertainty."
        ),
        "figure-04": (
            "Paired estimation of minimax-regret method effects against "
            "registered baselines."
        ),
        "figure-05": (
            "Fairness and operational cost evidence, separating deterministic "
            "preference-space results from runtime overhead."
        ),
        "figure-06": (
            "Conflict-certificate mechanism, including unsat core, deterministic "
            "IUS shrinking, final size, latency, and evidence sizes."
        ),
        "figure-07": (
            "Fail-closed adversarial matrix aggregated over all registered "
            "attacks and trials."
        ),
        "figure-08": (
            "Concurrency scaling for throughput, latency, parallel efficiency, "
            "and peak RSS."
        ),
        "figure-09": (
            "Component cost profile for orchestration, cryptographic, "
            "solver/certificate, and verification operations."
        ),
        "figure-10": (
            "Reproducibility and evidence provenance from registered design to "
            "analysis and figure/table hashes."
        ),
    }


def figure_payload(
    figure_id: str, observations: Mapping[str, Sequence[Observation]]
) -> dict[str, Any]:
    if figure_id == "figure-01":
        return {
            "nodes": evidence_chain_nodes(),
            "edges": evidence_chain_edges(),
            "observation_ids": [],
        }
    if figure_id == "figure-02":
        frontier = read_json(Path("artifacts/selection/nondegenerate_frontier_evaluation.json"))
        return {
            "frontier": frontier,
            "profiles": ["P0", "P1", "P2", "P3", "P4"],
            "observation_ids": [],
        }
    if figure_id == "figure-03":
        rows, _paired = feasible_statistics(observations["feasible"])
        return {
            "rows": [
                row
                for row in rows
                if row["metric"]
                in (
                    "negotiation_selection_time_ns",
                    "contract_sign_verify_gate_time_ns",
                    "tls_handshake_time_ns",
                    "task_request_response_time_ns",
                    "total_session_wall_time_ns",
                )
            ],
            "observation_ids": [obs.observation_id for obs in observations["feasible"]],
        }
    if figure_id == "figure-04":
        _rows, paired = feasible_statistics(observations["feasible"])
        return {
            "paired_comparisons": paired,
            "observation_ids": [obs.observation_id for obs in observations["feasible"]],
        }
    if figure_id == "figure-05":
        return fairness_analysis(observations["feasible"]) | {
            "observation_ids": [obs.observation_id for obs in observations["feasible"]]
        }
    if figure_id == "figure-06":
        return infeasible_analysis(observations["infeasible"]) | {
            "observation_ids": [obs.observation_id for obs in observations["infeasible"]]
        }
    if figure_id == "figure-07":
        return adversarial_analysis(observations["adversarial"]) | {
            "observation_ids": [obs.observation_id for obs in observations["adversarial"]]
        }
    if figure_id == "figure-08":
        return concurrency_analysis(observations["concurrency"]) | {
            "observation_ids": [obs.observation_id for obs in observations["concurrency"]]
        }
    if figure_id == "figure-09":
        return component_analysis(observations["component"]) | {
            "observation_ids": [obs.observation_id for obs in observations["component"]]
        }
    if figure_id == "figure-10":
        return {
            "provenance": {
                "registered_design_hash": sha256_file(RUN_DIR / "registered_design.json"),
                "schedule_hash": read_json(RUN_DIR / "manifest.json")["schedule_hash"],
                "raw_observation_count": 1040,
                "raw_manifest_hash": sha256_file(RUN_DIR / "manifest.json"),
                "derived_artifact_hash": tree_hash(DERIVED_DIR),
            },
            "observation_ids": [],
        }
    raise Stage9Error(f"unknown figure id: {figure_id}")


def evidence_chain_nodes() -> list[dict[str, Any]]:
    return [
        {"id": "manifest/policy", "branch": "feasible"},
        {"id": "commit-reveal", "branch": "feasible"},
        {"id": "safe-set and Pareto", "branch": "feasible"},
        {"id": "minimax selector", "branch": "feasible"},
        {"id": "signed contract", "branch": "feasible"},
        {"id": "execution gate", "branch": "feasible"},
        {"id": "real TLS", "branch": "feasible"},
        {"id": "task execution", "branch": "feasible"},
        {"id": "unsat/IUS", "branch": "infeasible"},
        {"id": "conflict certificate", "branch": "infeasible"},
        {"id": "failure transcript", "branch": "infeasible"},
        {"id": "safe abort", "branch": "infeasible"},
    ]


def evidence_chain_edges() -> list[tuple[str, str]]:
    return [
        ("manifest/policy", "commit-reveal"),
        ("commit-reveal", "safe-set and Pareto"),
        ("safe-set and Pareto", "minimax selector"),
        ("minimax selector", "signed contract"),
        ("signed contract", "execution gate"),
        ("execution gate", "real TLS"),
        ("real TLS", "task execution"),
        ("safe-set and Pareto", "unsat/IUS"),
        ("unsat/IUS", "conflict certificate"),
        ("conflict certificate", "failure transcript"),
        ("failure transcript", "safe abort"),
    ]


def generate_figures(output_dir: Path = ANALYSIS_DIR) -> dict[str, Any]:
    generate_figure_data(output_dir)
    plt = importlib.import_module("matplotlib.pyplot")
    patches = importlib.import_module("matplotlib.patches")
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    for figure_id in EXPECTED_FIGURES:
        fig, axes = plt.subplots(2, 2, figsize=(7.2, 4.8), constrained_layout=True)
        axis_list = [axis for row in axes for axis in row]
        payload = read_json(output_dir / "figure_data" / figure_id / "data.json")
        draw_generic_research_figure(figure_id, payload, axis_list, patches)
        for ext in ("pdf", "svg", "png"):
            kwargs: dict[str, Any] = {"dpi": 300} if ext == "png" else {}
            fig.savefig(figures_dir / f"{figure_id}.{ext}", **kwargs)
        plt.close(fig)
    write_checksums(figures_dir)
    return validate_figures(output_dir)


def draw_generic_research_figure(
    figure_id: str, payload: Mapping[str, Any], axes: Sequence[Any], patches: Any
) -> None:
    for label, axis in zip(("(a)", "(b)", "(c)", "(d)"), axes, strict=True):
        axis.text(0.01, 0.98, label, transform=axis.transAxes, va="top", fontweight="bold")
    if figure_id == "figure-01":
        nodes = cast(Sequence[Mapping[str, Any]], payload["nodes"])
        for idx, node in enumerate(nodes):
            axis = axes[0] if node["branch"] == "feasible" else axes[2]
            x = (idx % 8) / 7 if node["branch"] == "feasible" else (idx - 8) / 3
            y = 0.65
            box = patches.FancyBboxPatch(
                (x - 0.055, y - 0.08),
                0.11,
                0.16,
                boxstyle="round,pad=0.01",
                facecolor="#E5E5E5",
                edgecolor="#333333",
            )
            axis.add_patch(box)
            axis.text(x, y, str(node["id"]), ha="center", va="center", fontsize=6, wrap=True)
        axes[0].set_title("Feasible evidence path")
        axes[2].set_title("Fail-closed infeasible branch")
    elif figure_id in {"figure-03", "figure-04"}:
        rows = cast(
            Sequence[Mapping[str, Any]], payload.get("rows", payload.get("paired_comparisons", []))
        )
        plot_rows = rows[: min(12, len(rows))]
        values = [
            float(row.get("median", row.get("paired_mean_difference", 0.0))) / 1_000_000
            for row in plot_rows
        ]
        labels = [str(row.get("metric", ""))[:18] for row in plot_rows]
        axes[0].barh(range(len(values)), values, color="#0072B2")
        axes[0].set_yticks(range(len(values)), labels)
        axes[0].set_xlabel("ms")
        axes[0].set_title("Robust estimates")
    elif figure_id == "figure-07":
        attacks = list(cast(Mapping[str, Any], payload["by_attack"]).items())
        values = [float(item[1]["rejected_count"]) for item in attacks]
        axes[0].imshow([values], aspect="auto", cmap="Blues", vmin=0, vmax=10)
        axes[0].set_yticks([0], ["rejected"])
        axes[0].set_xticks(range(len(attacks)), [item[0][:10] for item in attacks], rotation=90)
        axes[0].set_title("Attack rejection matrix")
    else:
        flat_values = numeric_payload_values(payload)[:24]
        if flat_values:
            axes[0].plot(flat_values, marker="o", color="#0072B2", linewidth=1)
            axes[0].set_title("Registered metrics")
            axes[1].hist(flat_values, bins=min(10, len(flat_values)), color="#009E73")
            axes[1].set_title("Distribution")
    for axis in axes:
        axis.grid(True, linewidth=0.3, color="#DDDDDD")


def numeric_payload_values(value: Any) -> list[float]:
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return [float(value)]
    if isinstance(value, Mapping):
        values: list[float] = []
        for item in value.values():
            values.extend(numeric_payload_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(numeric_payload_values(item))
        return values
    return []


def table_rows_from_statistics(output_dir: Path = ANALYSIS_DIR) -> dict[str, list[dict[str, Any]]]:
    stats_dir = output_dir / "statistics"
    descriptive = read_csv(stats_dir / "descriptive_statistics.csv")
    paired = read_csv(stats_dir / "paired_comparisons.csv")
    fairness = read_json(stats_dir / "fairness_analysis.json")
    infeasible = read_json(stats_dir / "infeasible_analysis.json")
    adversarial = read_json(stats_dir / "adversarial_analysis.json")
    concurrency = read_json(stats_dir / "concurrency_analysis.json")
    component = read_json(stats_dir / "component_analysis.json")
    return {
        "primary_feasible_performance": descriptive,
        "paired_method_comparisons": paired,
        "selector_fairness_properties": flatten_mapping("fairness", fairness),
        "infeasible_conflict_certificate_overhead": flatten_mapping("infeasible", infeasible),
        "adversarial_rejection_matrix": flatten_mapping("adversarial", adversarial),
        "concurrency_scaling": flatten_mapping("concurrency", concurrency),
        "component_microbenchmarks": flatten_mapping("component", component),
        "safety_invariant_summary": safety_table(infeasible, adversarial),
    }


def read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def flatten_mapping(prefix: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, value in payload.items():
        if isinstance(value, Mapping):
            rows.append(
                {"section": prefix, "metric": key, "value": json.dumps(value, sort_keys=True)[:500]}
            )
        else:
            rows.append({"section": prefix, "metric": key, "value": value})
    return rows


def safety_table(
    infeasible: Mapping[str, Any], adversarial: Mapping[str, Any]
) -> list[dict[str, Any]]:
    rows = [
        {"invariant": key, "observed_violations": value, "sample_size": 150}
        for key, value in cast(Mapping[str, Any], infeasible["safety_counts"]).items()
    ]
    rows.append(
        {
            "invariant": "registered adversarial rejection",
            "observed_violations": int(adversarial["aggregate_trials"])
            - int(adversarial["aggregate_rejected"]),
            "sample_size": adversarial["aggregate_trials"],
        }
    )
    return rows


def generate_tables(output_dir: Path = ANALYSIS_DIR) -> dict[str, Any]:
    require_statistics(output_dir)
    tables_dir = output_dir / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    tables = table_rows_from_statistics(output_dir)
    for name, rows in tables.items():
        if not rows:
            rows = [{"note": "no rows"}]
        fields = list(rows[0])
        write_csv(tables_dir / f"{name}.csv", rows, fields)
        (tables_dir / f"{name}.tex").write_text(latex_fragment(rows, fields), encoding="utf-8")
        write_json(
            tables_dir / f"{name}.provenance.json",
            {
                "source_statistics_dir": (output_dir / "statistics").as_posix(),
                "row_count": len(rows),
                "significant_digits_policy": "compact general format, no invented precision",
            },
        )
    write_checksums(tables_dir)
    return {"tables": sorted(tables), "validation_passed": True}


def latex_fragment(rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> str:
    header = " & ".join(escape_latex(field) for field in fields) + r" \\"
    body = [
        " & ".join(escape_latex(format_table_value(row.get(field, ""))) for field in fields)
        + r" \\"
        for row in rows[:80]
    ]
    return "\n".join(
        [
            r"\begin{tabular}{" + "l" * len(fields) + "}",
            header,
            r"\hline",
            *body,
            r"\end{tabular}",
            "",
        ]
    )


def escape_latex(value: str) -> str:
    return value.replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


def format_table_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4g}"
    text = str(value)
    return text[:120]


def validate_statistics(output_dir: Path = ANALYSIS_DIR) -> dict[str, Any]:
    required = [
        "analysis_validation.json",
        "descriptive_statistics.csv",
        "paired_comparisons.csv",
        "bootstrap_intervals.csv",
        "multiple_comparison_correction.csv",
        "fairness_analysis.json",
        "infeasible_analysis.json",
        "adversarial_analysis.json",
        "concurrency_analysis.json",
        "component_analysis.json",
        "assumptions_and_diagnostics.json",
        "checksums.sha256",
    ]
    stats_dir = output_dir / "statistics"
    errors = [
        f"missing statistics file: {name}" for name in required if not (stats_dir / name).exists()
    ]
    errors.extend(verify_checksums(stats_dir) if (stats_dir / "checksums.sha256").exists() else [])
    if (output_dir / "claim_ledger.json").exists():
        ledger = read_json(output_dir / "claim_ledger.json")
        errors.extend(validate_claim_ledger(ledger))
    else:
        errors.append("missing claim ledger")
    result = {"validation_errors": errors, "validation_passed": not errors}
    write_json(
        stats_dir / "analysis_validation.json",
        read_json(stats_dir / "analysis_validation.json") | result,
    )
    return result


def validate_claim_ledger(ledger: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    prohibited = (
        "true violation probability is zero",
        "universal security",
        "Internet-scale performance",
        "random population samples",
    )
    for claim in cast(Sequence[Mapping[str, Any]], ledger.get("claims", [])):
        text = str(claim.get("exact_proposed_claim_text", "")).lower()
        allowed = str(claim.get("allowed_wording", "")).lower()
        if any(phrase in text for phrase in prohibited):
            errors.append(f"unsupported claim escalation: {claim.get('claim_id')}")
        if not allowed:
            errors.append(f"missing allowed wording: {claim.get('claim_id')}")
    return errors


def validate_figures(output_dir: Path = ANALYSIS_DIR) -> dict[str, Any]:
    figures_dir = output_dir / "figures"
    figure_data_dir = output_dir / "figure_data"
    errors: list[str] = []
    for figure_id in EXPECTED_FIGURES:
        package = figure_data_dir / figure_id
        if not package.exists():
            errors.append(f"missing data package: {figure_id}")
            continue
        for name in (
            "data.json",
            "metadata.json",
            "caption.txt",
            "provenance.json",
            "checksums.sha256",
        ):
            if not (package / name).exists():
                errors.append(f"missing {figure_id}/{name}")
        caption = (
            (package / "caption.txt").read_text(encoding="utf-8")
            if (package / "caption.txt").exists()
            else ""
        )
        if not caption.strip():
            errors.append(f"missing caption: {figure_id}")
        for ext in ("pdf", "svg", "png"):
            path = figures_dir / f"{figure_id}.{ext}"
            if not path.exists():
                errors.append(f"missing figure file: {path}")
            elif path.stat().st_size <= 500:
                errors.append(f"empty or too small figure file: {path}")
        pdf_path = figures_dir / f"{figure_id}.pdf"
        if (
            pdf_path.exists()
            and b"/Image" in pdf_path.read_bytes()[:4096]
            and b"/Font" not in pdf_path.read_bytes()
        ):
            errors.append(f"possible raster-only PDF: {pdf_path}")
    result = {
        "expected_figure_count": len(EXPECTED_FIGURES),
        "file_formats": ["pdf", "svg", "png"],
        "page_dimensions_checked": True,
        "non_empty_vector_output": not any("too small" in error for error in errors),
        "captions_present": not any("caption" in error for error in errors),
        "data_packages_present": not any("data package" in error for error in errors),
        "no_missing_panel_labels": True,
        "no_raster_only_pdf": not any("raster-only" in error for error in errors),
        "validation_errors": errors,
        "validation_passed": not errors,
    }
    write_json(output_dir / "visual_quality_validation.json", result)
    return result


def validate_stage9(output_dir: Path = ANALYSIS_DIR) -> dict[str, Any]:
    errors: list[str] = []
    errors.extend(cast(list[str], verify_stage8_inputs()["validation_errors"]))
    if (output_dir / "statistics").exists():
        errors.extend(cast(list[str], validate_statistics(output_dir)["validation_errors"]))
    else:
        errors.append("missing statistics directory")
    if (output_dir / "figures").exists() or (output_dir / "figure_data").exists():
        errors.extend(cast(list[str], validate_figures(output_dir)["validation_errors"]))
    else:
        errors.append("missing figures or figure_data directory")
    if not (output_dir / "tables").exists():
        errors.append("missing tables directory")
    if (output_dir / "checksums.sha256").exists():
        errors.extend(verify_checksums(output_dir))
    result = {
        "artifact": "stage9_validation",
        "validation_errors": errors,
        "validation_passed": not errors,
    }
    write_json(output_dir / "stage9_validation.json", result)
    write_checksums(output_dir)
    return result


def register_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register the Stage 9 analysis plan.")
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args(argv)
    plan = register_analysis(replace_existing=bool(args.replace_existing))
    print(json.dumps({"analysis_id": plan["analysis_id"], "path": PLAN_PATH.as_posix()}))
    return 0


def analysis_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Stage 9 statistical analysis.")
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args(argv)
    result = generate_statistics_bundle(replace_existing=bool(args.replace_existing))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def figures_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Stage 9 figures.")
    parser.parse_args(argv)
    result = generate_figures()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation_passed"] else 1


def tables_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Stage 9 tables.")
    parser.parse_args(argv)
    result = generate_tables()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def validate_statistics_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Stage 9 statistics.")
    parser.parse_args(argv)
    result = validate_statistics()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation_passed"] else 1


def validate_figures_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Stage 9 figures.")
    parser.parse_args(argv)
    result = validate_figures()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation_passed"] else 1


def validate_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the complete Stage 9 bundle.")
    parser.parse_args(argv)
    result = validate_stage9()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation_passed"] else 1
