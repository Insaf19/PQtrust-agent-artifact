#!/usr/bin/env python3
"""Stage 3D paired block-normalized cryptographic cost calibration."""

from __future__ import annotations

import argparse
import math
import random
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from compare_crypto_calibrations import compatibility_report_for_resolved
from pqtrust_agent.crypto.smoke_validation import atomic_write_json, write_checksums
from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.metrics.calibration_config_resolver import resolve_raw_run_config
from pqtrust_agent.metrics.calibration_models import CryptoCalibrationConfig
from pqtrust_agent.metrics.descriptive import median, quantile
from pqtrust_agent.metrics.run_manifest import git_commit, git_dirty, utc_now
from pqtrust_agent.metrics.validation import (
    load_json,
    load_jsonl,
    raw_run_checksum,
    validate_raw_run,
)
from pqtrust_agent.models.catalog import load_profile_catalog

TLS_PROFILE_GROUPS: dict[str, str] = {
    "P0": "X25519",
    "P1": "X25519MLKEM768",
    "P2": "SecP256r1MLKEM768",
    "P3": "MLKEM768",
    "P4": "SecP384r1MLKEM1024",
}
TLS_GROUP_PROFILES = {group: profile for profile, group in TLS_PROFILE_GROUPS.items()}
TLS_METRICS = (
    "wall_time_ns",
    "process_cpu_time_ns",
    "client_to_server_bytes",
    "server_to_client_bytes",
    "total_handshake_bytes",
)
TLS_TIMING_METRICS = ("wall_time_ns", "process_cpu_time_ns")
TLS_RATIO_NAMES = {
    "wall_time_ns": "wall_time_ratio",
    "process_cpu_time_ns": "process_cpu_time_ratio",
    "client_to_server_bytes": "client_to_server_bytes_ratio",
    "server_to_client_bytes": "server_to_client_bytes_ratio",
    "total_handshake_bytes": "total_handshake_bytes_ratio",
}
MLDSA_METRICS = ("sign_time_ns", "verify_time_ns", "signature_size_bytes")
BOOTSTRAP_SEED = 20260841
BOOTSTRAP_ITERATIONS = 10_000
STABILITY_THRESHOLD = 0.10
FLOAT_TOLERANCE = 1e-12
RECIPROCAL_REL_TOLERANCE = 1e-12
RECIPROCAL_ABS_TOLERANCE = 1e-12


@dataclass(frozen=True)
class PairedBlock:
    run_id: str
    replicate_id: str
    block: int
    records_by_profile: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class MldsaBlock:
    run_id: str
    replicate_id: str
    block: int
    message_size_bytes: int
    records_by_algorithm: Mapping[str, Mapping[str, Any]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run-id", required=True)
    parser.add_argument("--confirmatory-run-id", required=True)
    parser.add_argument("--raw-root", type=Path, default=Path("runs/raw/crypto_calibration"))
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--reference-profile", default="P0")
    parser.add_argument("--replace-existing", action="store_true")
    return parser.parse_args()


def _replicate_id(replicate_dir: Path) -> str:
    return replicate_dir.name


def validate_catalog_profile_mapping(repo_root: Path, expected: Mapping[str, str]) -> str:
    catalog = load_profile_catalog(repo_root / "configs/profiles/trust_profiles.yaml")
    observed = {profile.profile_id: profile.tls_group for profile in catalog.profiles}
    if observed != dict(expected):
        raise ValueError(f"profile catalog TLS mapping mismatch: {observed}")
    return catalog.catalog_hash()


def _require_success(record: Mapping[str, Any], label: str) -> None:
    if record.get("success") is not True:
        raise ValueError(f"{label}: unsuccessful record")


def pair_tls_blocks(
    run_id: str, run_dir: Path, config: CryptoCalibrationConfig
) -> list[PairedBlock]:
    expected_groups = set(TLS_PROFILE_GROUPS.values())
    if set(config.tls_groups) != expected_groups:
        raise ValueError("configuration TLS groups do not match Stage 3D profile mapping")
    paired: list[PairedBlock] = []
    replicate_dirs = sorted(path for path in (run_dir / "replicates").iterdir() if path.is_dir())
    for replicate_dir in replicate_dirs:
        replicate_id = _replicate_id(replicate_dir)
        by_block: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for record in load_jsonl(replicate_dir / "tls_handshakes.jsonl"):
            by_block[int(record["block"])].append(record)
        for block in range(config.measured_blocks):
            records = by_block.get(block, [])
            counts = Counter(str(record.get("requested_group")) for record in records)
            if counts != Counter(expected_groups):
                raise ValueError(
                    f"{run_id}/{replicate_id}/TLS block {block}: expected exactly one "
                    f"successful observation for each profile, observed {dict(counts)}"
                )
            records_by_profile: dict[str, Mapping[str, Any]] = {}
            for record in records:
                _require_success(record, f"{run_id}/{replicate_id}/TLS block {block}")
                group = str(record["requested_group"])
                profile = TLS_GROUP_PROFILES[group]
                records_by_profile[profile] = record
            paired.append(
                PairedBlock(
                    run_id=run_id,
                    replicate_id=replicate_id,
                    block=block,
                    records_by_profile=records_by_profile,
                )
            )
    return paired


def metric_value(record: Mapping[str, Any], metric: str) -> float:
    if metric not in record:
        raise ValueError(f"{metric} is missing")
    value = record[metric]
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError(f"{metric} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise ValueError(f"{metric} must be finite and positive")
    return numeric


def finite_positive_ratio(
    numerator: int | float,
    denominator: int | float,
    *,
    label: str,
) -> float:
    if isinstance(numerator, bool) or not isinstance(numerator, int | float):
        raise ValueError(f"{label}: numerator must be numeric")
    if isinstance(denominator, bool) or not isinstance(denominator, int | float):
        raise ValueError(f"{label}: denominator must be numeric")
    left = float(numerator)
    right = float(denominator)
    if not math.isfinite(left) or left <= 0:
        raise ValueError(f"{label}: numerator must be finite and positive")
    if not math.isfinite(right) or right <= 0:
        raise ValueError(f"{label}: denominator must be finite and positive")
    return left / right


def metric_ratio(
    numerator_record: Mapping[str, Any],
    denominator_record: Mapping[str, Any],
    metric: str,
    *,
    label: str,
) -> float:
    if metric not in numerator_record:
        raise ValueError(f"{label}: numerator {metric} is missing")
    if metric not in denominator_record:
        raise ValueError(f"{label}: denominator {metric} is missing")
    return finite_positive_ratio(
        numerator_record[metric],
        denominator_record[metric],
        label=f"{label}/{metric}",
    )


def _record_identity(record: Mapping[str, Any], field: str) -> str | int | None:
    value = record.get(field)
    if value is None:
        return None
    if isinstance(value, str | int):
        return value
    return str(value)


def _validate_record_identity(
    block: PairedBlock, profile: str, record: Mapping[str, Any], metric: str
) -> None:
    expected: dict[str, str | int] = {
        "run_id": block.run_id,
        "replicate_id": block.replicate_id,
        "block": block.block,
    }
    for field, expected_value in expected.items():
        observed = _record_identity(record, field)
        if observed is None:
            continue
        if observed != expected_value:
            raise ValueError(
                f"{block.run_id}/{block.replicate_id}/TLS block {block.block}: "
                f"{profile}/{metric} record has mismatched {field}={observed!r}; "
                f"expected {expected_value!r}"
            )


def _validate_complete_profile_block(block: PairedBlock) -> None:
    observed = set(block.records_by_profile)
    expected = set(TLS_PROFILE_GROUPS)
    if observed != expected:
        raise ValueError(
            f"{block.run_id}/{block.replicate_id}/TLS block {block.block}: "
            f"expected profiles {sorted(expected)}, observed {sorted(observed)}"
        )


def relative_tls_rows(
    blocks: Sequence[PairedBlock], reference_profile: str = "P0"
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for block in blocks:
        _validate_complete_profile_block(block)
        reference = block.records_by_profile[reference_profile]
        for profile in sorted(TLS_PROFILE_GROUPS):
            record = block.records_by_profile[profile]
            ratios: dict[str, float] = {}
            differences: dict[str, float] = {}
            logs: dict[str, float] = {}
            for metric in TLS_METRICS:
                _validate_record_identity(block, profile, record, metric)
                _validate_record_identity(block, reference_profile, reference, metric)
                numerator = metric_value(record, metric)
                denominator = metric_value(reference, metric)
                ratio = finite_positive_ratio(
                    numerator,
                    denominator,
                    label=(
                        f"{block.run_id}/{block.replicate_id}/TLS block {block.block}/"
                        f"{profile}/{reference_profile}/{metric}"
                    ),
                )
                difference = numerator - denominator
                if profile == reference_profile:
                    ratio = 1.0
                    difference = 0.0
                ratios[TLS_RATIO_NAMES[metric]] = ratio
                differences[metric] = difference
                if metric in TLS_TIMING_METRICS:
                    logs[f"log_{TLS_RATIO_NAMES[metric]}"] = math.log(ratio)
            rows.append(
                {
                    "run_id": block.run_id,
                    "replicate_id": block.replicate_id,
                    "block": block.block,
                    "profile_id": profile,
                    "tls_group": TLS_PROFILE_GROUPS[profile],
                    "ratios_to_reference": ratios,
                    "absolute_differences_from_reference": differences,
                    "log_timing_ratios_to_reference": logs,
                }
            )
    return rows


def _ratio_records_by_profile_metric(
    rows: Sequence[Mapping[str, Any]], metric: str
) -> dict[str, dict[str, list[float]]]:
    ratio_name = TLS_RATIO_NAMES[metric]
    grouped: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        profile = str(row["profile_id"])
        replicate_key = f"{row['run_id']}:{row['replicate_id']}"
        ratios = row["ratios_to_reference"]
        if not isinstance(ratios, Mapping):
            raise ValueError("ratios_to_reference must be a mapping")
        grouped[profile][replicate_key].append(float(ratios[ratio_name]))
    return {profile: dict(replicates) for profile, replicates in grouped.items()}


def hierarchical_summary_for_metric(
    rows: Sequence[Mapping[str, Any]],
    metric: str,
    baseline_run_id: str,
    confirmatory_run_id: str,
) -> dict[str, Any]:
    grouped = _ratio_records_by_profile_metric(rows, metric)
    output: dict[str, Any] = {}
    for profile in sorted(TLS_PROFILE_GROUPS):
        replicate_medians: dict[str, float] = {}
        for run_id in (baseline_run_id, confirmatory_run_id):
            for replicate in ("replicate-01", "replicate-02", "replicate-03"):
                key = f"{run_id}:{replicate}"
                replicate_medians[key] = median(grouped[profile][key])
        baseline_values = [
            replicate_medians[f"{baseline_run_id}:replicate-{index:02d}"] for index in range(1, 4)
        ]
        confirmatory_values = [
            replicate_medians[f"{confirmatory_run_id}:replicate-{index:02d}"]
            for index in range(1, 4)
        ]
        baseline_run_median = median(baseline_values)
        confirmatory_run_median = median(confirmatory_values)
        all_replicate_medians = list(replicate_medians.values())
        replicate_range = max(all_replicate_medians) - min(all_replicate_medians)
        final = median([baseline_run_median, confirmatory_run_median])
        relative_difference = (
            0.0
            if baseline_run_median == 0
            else abs(confirmatory_run_median - baseline_run_median) / baseline_run_median
        )
        output[profile] = {
            "profile_id": profile,
            "tls_group": TLS_PROFILE_GROUPS[profile],
            "metric": metric,
            "replicate_medians": replicate_medians,
            "baseline_run_median": baseline_run_median,
            "confirmatory_run_median": confirmatory_run_median,
            "final_relative_estimate": final,
            "minimum_replicate_median": min(all_replicate_medians),
            "maximum_replicate_median": max(all_replicate_medians),
            "replicate_relative_range": 0.0 if final == 0 else replicate_range / final,
            "baseline_confirmatory_relative_difference": relative_difference,
        }
    return output


def hierarchical_tls_summary(
    rows: Sequence[Mapping[str, Any]], baseline_run_id: str, confirmatory_run_id: str
) -> dict[str, Any]:
    return {
        metric: hierarchical_summary_for_metric(rows, metric, baseline_run_id, confirmatory_run_id)
        for metric in TLS_METRICS
    }


def hierarchical_paired_bootstrap_ci(
    blocks: Sequence[PairedBlock],
    profile: str,
    metric: str,
    *,
    iterations: int = BOOTSTRAP_ITERATIONS,
    seed: int = BOOTSTRAP_SEED,
    reference_profile: str = "P0",
) -> dict[str, float | int]:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    by_run_rep: dict[str, dict[str, list[PairedBlock]]] = defaultdict(lambda: defaultdict(list))
    for block in blocks:
        by_run_rep[block.run_id][block.replicate_id].append(block)
    runs = sorted(by_run_rep)
    if len(runs) != 2:
        raise ValueError("paired bootstrap requires exactly two runs")
    rng = random.Random(seed)
    bootstrapped: list[float] = []
    for _ in range(iterations):
        run_medians: list[float] = []
        for _run_slot in range(2):
            sampled_run = rng.choice(runs)
            replicates = sorted(by_run_rep[sampled_run])
            replicate_medians: list[float] = []
            for _rep_slot in range(3):
                sampled_rep = rng.choice(replicates)
                source_blocks = by_run_rep[sampled_run][sampled_rep]
                sampled_ratios = []
                for _block_slot in range(len(source_blocks)):
                    sampled_block = rng.choice(source_blocks)
                    sampled_ratios.append(
                        metric_ratio(
                            sampled_block.records_by_profile[profile],
                            sampled_block.records_by_profile[reference_profile],
                            metric,
                            label=(
                                f"{sampled_block.run_id}/{sampled_block.replicate_id}/"
                                f"TLS block {sampled_block.block}/{profile}/{reference_profile}"
                            ),
                        )
                    )
                replicate_medians.append(median(sampled_ratios))
            run_medians.append(median(replicate_medians))
        bootstrapped.append(median(run_medians))
    return {
        "seed": seed,
        "iterations": iterations,
        "confidence_level": 0.95,
        "lower": quantile(bootstrapped, 0.025),
        "upper": quantile(bootstrapped, 0.975),
    }


def tls_bootstrap_intervals(blocks: Sequence[PairedBlock]) -> dict[str, Any]:
    return {
        profile: {
            metric: hierarchical_paired_bootstrap_ci(blocks, profile, metric)
            for metric in TLS_METRICS
        }
        for profile in sorted(TLS_PROFILE_GROUPS)
    }


def hierarchical_pairwise_bootstrap_ci(
    blocks: Sequence[PairedBlock],
    left: str,
    right: str,
    metric: str,
    *,
    iterations: int = BOOTSTRAP_ITERATIONS,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, float | int]:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    by_run_rep: dict[str, dict[str, list[PairedBlock]]] = defaultdict(lambda: defaultdict(list))
    for block in blocks:
        by_run_rep[block.run_id][block.replicate_id].append(block)
    runs = sorted(by_run_rep)
    if len(runs) != 2:
        raise ValueError("paired bootstrap requires exactly two runs")
    rng = random.Random(seed)
    bootstrapped: list[float] = []
    for _ in range(iterations):
        run_medians: list[float] = []
        for _run_slot in range(2):
            sampled_run = rng.choice(runs)
            replicates = sorted(by_run_rep[sampled_run])
            replicate_medians: list[float] = []
            for _rep_slot in range(3):
                sampled_rep = rng.choice(replicates)
                source_blocks = by_run_rep[sampled_run][sampled_rep]
                sampled_ratios = []
                for _block_slot in range(len(source_blocks)):
                    sampled_block = rng.choice(source_blocks)
                    sampled_ratios.append(
                        metric_ratio(
                            sampled_block.records_by_profile[left],
                            sampled_block.records_by_profile[right],
                            metric,
                            label=(
                                f"{sampled_block.run_id}/{sampled_block.replicate_id}/"
                                f"TLS block {sampled_block.block}/{left}/{right}"
                            ),
                        )
                    )
                replicate_medians.append(median(sampled_ratios))
            run_medians.append(median(replicate_medians))
        bootstrapped.append(median(run_medians))
    return {
        "seed": seed,
        "iterations": iterations,
        "confidence_level": 0.95,
        "lower": quantile(bootstrapped, 0.025),
        "upper": quantile(bootstrapped, 0.975),
    }


def pairwise_hierarchical_estimate(
    blocks: Sequence[PairedBlock],
    left: str,
    right: str,
    metric: str,
    *,
    bootstrap_iterations: int = BOOTSTRAP_ITERATIONS,
) -> dict[str, Any]:
    ratio_by_run_rep: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    difference_by_run_rep: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for block in blocks:
        _validate_complete_profile_block(block)
        left_record = block.records_by_profile[left]
        right_record = block.records_by_profile[right]
        _validate_record_identity(block, left, left_record, metric)
        _validate_record_identity(block, right, right_record, metric)
        left_value = metric_value(left_record, metric)
        right_value = metric_value(right_record, metric)
        ratio_by_run_rep[block.run_id][block.replicate_id].append(
            finite_positive_ratio(
                left_value,
                right_value,
                label=(
                    f"{block.run_id}/{block.replicate_id}/TLS block {block.block}/"
                    f"{left}/{right}/{metric}"
                ),
            )
        )
        difference_by_run_rep[block.run_id][block.replicate_id].append(left_value - right_value)

    replicate_medians: dict[str, float] = {}
    replicate_median_differences: dict[str, float] = {}
    run_level_medians: dict[str, float] = {}
    run_level_median_differences: dict[str, float] = {}
    for run_id in sorted(ratio_by_run_rep):
        run_ratio_medians: list[float] = []
        run_difference_medians: list[float] = []
        for replicate_id in sorted(ratio_by_run_rep[run_id]):
            key = f"{run_id}:{replicate_id}"
            ratio_median = median(ratio_by_run_rep[run_id][replicate_id])
            difference_median = median(difference_by_run_rep[run_id][replicate_id])
            replicate_medians[key] = ratio_median
            replicate_median_differences[key] = difference_median
            run_ratio_medians.append(ratio_median)
            run_difference_medians.append(difference_median)
        run_level_medians[run_id] = median(run_ratio_medians)
        run_level_median_differences[run_id] = median(run_difference_medians)

    run_values = [run_level_medians[run_id] for run_id in sorted(run_level_medians)]
    run_difference_values = [
        run_level_median_differences[run_id] for run_id in sorted(run_level_median_differences)
    ]
    final = median(run_values)
    final_difference = median(run_difference_values)
    run_level_relative_difference = 0.0
    if len(run_values) == 2 and run_values[0] != 0:
        run_level_relative_difference = abs(run_values[1] - run_values[0]) / run_values[0]
    return {
        "directional_hierarchical_estimate": final,
        "median_ratio": final,
        "replicate_medians": replicate_medians,
        "run_level_medians": run_level_medians,
        "final_cross_run_estimate": final,
        "bootstrap_interval": hierarchical_pairwise_bootstrap_ci(
            blocks, left, right, metric, iterations=bootstrap_iterations
        ),
        "replicate_median_differences": replicate_median_differences,
        "run_level_median_differences": run_level_median_differences,
        "final_absolute_difference_estimate": final_difference,
        "median_difference": final_difference,
        "run_level_relative_difference": run_level_relative_difference,
        "observations": sum(
            len(replicate_values)
            for run_values_by_rep in ratio_by_run_rep.values()
            for replicate_values in run_values_by_rep.values()
        ),
        "byte_evidence_preserved_as_integers": metric.endswith("_bytes"),
        "aggregation_note": (
            "This is a directional hierarchical aggregate of observed paired-block "
            "ratios. The independently aggregated reverse direction is not required "
            "to be its exact reciprocal because even-sample medians average two "
            "central observations."
        ),
    }


def pairwise_tls_matrix(
    blocks: Sequence[PairedBlock], *, bootstrap_iterations: int = BOOTSTRAP_ITERATIONS
) -> dict[str, Any]:
    matrix: dict[str, Any] = {}
    for left in sorted(TLS_PROFILE_GROUPS):
        matrix[left] = {}
        for right in sorted(TLS_PROFILE_GROUPS):
            metric_rows: dict[str, Any] = {}
            for metric in TLS_METRICS:
                metric_rows[metric] = pairwise_hierarchical_estimate(
                    blocks, left, right, metric, bootstrap_iterations=bootstrap_iterations
                )
            matrix[left][right] = metric_rows
    add_symmetric_display_estimates(matrix)
    return matrix


def add_symmetric_display_estimates(matrix: dict[str, Any]) -> None:
    for left in sorted(TLS_PROFILE_GROUPS):
        for right in sorted(TLS_PROFILE_GROUPS):
            for metric in TLS_METRICS:
                if left == right:
                    matrix[left][right][metric]["symmetric_display_estimate"] = 1.0
                    continue
                canonical_left, canonical_right = sorted((left, right))
                canonical = float(
                    matrix[canonical_left][canonical_right][metric][
                        "directional_hierarchical_estimate"
                    ]
                )
                display = canonical if left == canonical_left else 1.0 / canonical
                matrix[left][right][metric]["symmetric_display_estimate"] = display
                matrix[left][right][metric]["symmetric_display_note"] = (
                    "Reciprocal display value derived from the canonical unordered pair. "
                    "It is not a replacement for the primary directional hierarchical "
                    "estimate."
                )


def verify_reciprocal_consistency(
    matrix: Mapping[str, Any],
    *,
    rel_tol: float = RECIPROCAL_REL_TOLERANCE,
    abs_tol: float = RECIPROCAL_ABS_TOLERANCE,
) -> None:
    """Reject inconsistent raw paired-block reciprocal products.

    This compatibility wrapper accepts the raw-block diagnostic mapping produced by
    ``tls_reciprocity_diagnostics``. It intentionally does not validate independently
    aggregated pairwise medians, because median(x/y) and median(y/x) need not multiply
    to one for an even number of positive observations.
    """

    if "validation_passed" in matrix:
        if matrix["validation_passed"] is not True:
            raise ValueError("raw paired-block reciprocal consistency failed")
        return
    raise ValueError(
        "reciprocal consistency must be validated on raw paired-block diagnostics, "
        "not on independently aggregated pairwise estimates"
    )


def tls_reciprocity_diagnostics(
    blocks: Sequence[PairedBlock],
    *,
    rel_tol: float = RECIPROCAL_REL_TOLERANCE,
    abs_tol: float = RECIPROCAL_ABS_TOLERANCE,
) -> dict[str, Any]:
    checked = 0
    failing = 0
    max_abs_error = 0.0
    max_rel_error = 0.0
    first_failure: str | None = None
    profiles = sorted(TLS_PROFILE_GROUPS)
    for block in blocks:
        _validate_complete_profile_block(block)
        for profile in profiles:
            for metric in TLS_METRICS:
                _validate_record_identity(
                    block, profile, block.records_by_profile[profile], metric
                )
        for left_index, left in enumerate(profiles):
            for right in profiles[left_index + 1 :]:
                for metric in TLS_METRICS:
                    label = (
                        f"{block.run_id}/{block.replicate_id}/TLS block {block.block}/"
                        f"{left}/{right}/{metric}"
                    )
                    left_record = block.records_by_profile[left]
                    right_record = block.records_by_profile[right]
                    forward = metric_ratio(left_record, right_record, metric, label=label)
                    reverse = metric_ratio(
                        right_record,
                        left_record,
                        metric,
                        label=(
                            f"{block.run_id}/{block.replicate_id}/TLS block {block.block}/"
                            f"{right}/{left}"
                        ),
                    )
                    product = forward * reverse
                    abs_error = abs(product - 1.0)
                    rel_error = abs_error
                    max_abs_error = max(max_abs_error, abs_error)
                    max_rel_error = max(max_rel_error, rel_error)
                    checked += 1
                    if not math.isclose(product, 1.0, rel_tol=rel_tol, abs_tol=abs_tol):
                        failing += 1
                        if first_failure is None:
                            first_failure = (
                                f"{block.run_id}/{block.replicate_id}/TLS block "
                                f"{block.block}: reciprocal product failed for "
                                f"{left}/{right}/{metric}; product={product!r}, "
                                f"abs_error={abs_error!r}, rel_error={rel_error!r}, "
                                f"rel_tol={rel_tol!r}, abs_tol={abs_tol!r}"
                            )
    diagnostic = {
        "checked_block_count": checked,
        "failing_block_count": failing,
        "maximum_absolute_product_error": max_abs_error,
        "maximum_relative_product_error": max_rel_error,
        "tolerance": {"rel_tol": rel_tol, "abs_tol": abs_tol},
        "validation_passed": failing == 0,
    }
    if first_failure is not None:
        diagnostic["first_failure"] = first_failure
        raise ValueError(first_failure)
    return diagnostic


def _absolute_timing_stability(artifact_root: Path, run_ids: Sequence[str]) -> dict[str, Any]:
    gates: dict[str, Any] = {}
    for run_id in run_ids:
        path = artifact_root / "calibration-quality" / run_id / "quality_gate.json"
        gate = load_json(path)
        gates[run_id] = {
            "timing_stability_passed": gate.get("timing_stability_passed") is True,
            "integrity_passed": gate.get("integrity_passed") is True,
            "source": str(path),
        }
    return {
        "absolute_timing_stability_passed": all(
            item["timing_stability_passed"] for item in gates.values()
        ),
        "source_gates": gates,
    }


def relative_quality_gate(
    summary: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    *,
    absolute_timing_stability: Mapping[str, Any],
    compatibility_passed: bool,
    complete_block_count: int,
    expected_block_count: int,
) -> dict[str, Any]:
    profile_gate: dict[str, Any] = {}
    for profile in sorted(TLS_PROFILE_GROUPS):
        timing_passes: dict[str, bool] = {}
        for metric in TLS_TIMING_METRICS:
            metric_summary = summary[metric][profile]
            interval = bootstrap[profile][metric]
            timing_passes[metric] = (
                metric_summary["baseline_confirmatory_relative_difference"]
                <= STABILITY_THRESHOLD
                and metric_summary["replicate_relative_range"] <= STABILITY_THRESHOLD
                and float(interval["lower"]) > 0
                and float(interval["upper"]) > 0
                and complete_block_count == expected_block_count
                and compatibility_passed
            )
        profile_gate[profile] = {
            "profile_id": profile,
            "tls_group": TLS_PROFILE_GROUPS[profile],
            "timing_metrics": timing_passes,
            "paired_relative_timing_stability_passed": all(timing_passes.values()),
        }
    all_profiles_pass = all(
        item["paired_relative_timing_stability_passed"] for item in profile_gate.values()
    )
    return {
        "schema_version": 1,
        "threshold": STABILITY_THRESHOLD,
        "absolute_timing_stability_passed": absolute_timing_stability[
            "absolute_timing_stability_passed"
        ],
        "absolute_timing_stability": absolute_timing_stability,
        "paired_relative_timing_stability_passed": all_profiles_pass,
        "relative_cost_usable_for_selector": all_profiles_pass,
        "complete_paired_blocks": complete_block_count,
        "expected_paired_blocks": expected_block_count,
        "profile_gates": profile_gate,
        "interpretation": (
            "Absolute timing instability remains visible; selector usability is based on "
            "all profiles passing paired relative timing gates."
        ),
    }


def pair_mldsa_blocks(
    run_id: str, run_dir: Path, config: CryptoCalibrationConfig
) -> list[MldsaBlock]:
    expected_algorithms = set(config.mldsa_algorithms)
    paired: list[MldsaBlock] = []
    replicate_dirs = sorted(path for path in (run_dir / "replicates").iterdir() if path.is_dir())
    for replicate_dir in replicate_dirs:
        replicate_id = _replicate_id(replicate_dir)
        by_case: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
        for record in load_jsonl(replicate_dir / "mldsa.jsonl"):
            key = (int(record["block"]), int(record["message_size_bytes"]))
            by_case[key].append(record)
        for block in range(config.measured_blocks):
            for size in config.mldsa_message_sizes_bytes:
                records = by_case[(block, size)]
                counts = Counter(str(record.get("algorithm")) for record in records)
                if counts != Counter(expected_algorithms):
                    raise ValueError(
                        f"{run_id}/{replicate_id}/ML-DSA block {block}/size {size}: "
                        f"expected complete algorithm pair, observed {dict(counts)}"
                    )
                by_algorithm: dict[str, Mapping[str, Any]] = {}
                for record in records:
                    _require_success(record, f"{run_id}/{replicate_id}/ML-DSA block {block}")
                    by_algorithm[str(record["algorithm"])] = record
                paired.append(
                    MldsaBlock(
                        run_id=run_id,
                        replicate_id=replicate_id,
                        block=block,
                        message_size_bytes=int(size),
                        records_by_algorithm=by_algorithm,
                    )
                )
    return paired


def mldsa_relative_summary(blocks: Sequence[MldsaBlock]) -> dict[str, Any]:
    output: dict[str, Any] = {
        "schema_version": 1,
        "comparison": "ML-DSA-65 versus ML-DSA-87",
        "contract_payload_note": (
            "Canonical contract and manifest payload sizes have not yet been measured."
        ),
        "message_sizes": {},
    }
    by_size: dict[int, list[MldsaBlock]] = defaultdict(list)
    for block in blocks:
        by_size[block.message_size_bytes].append(block)
    for size, size_blocks in sorted(by_size.items()):
        metrics: dict[str, Any] = {}
        for metric in MLDSA_METRICS:
            ratios = []
            differences = []
            for block in size_blocks:
                left = metric_value(block.records_by_algorithm["ML-DSA-65"], metric)
                right = metric_value(block.records_by_algorithm["ML-DSA-87"], metric)
                ratios.append(left / right)
                differences.append(left - right)
            metrics[metric] = {
                "median_ratio_mldsa65_over_mldsa87": median(ratios),
                "median_difference_mldsa65_minus_mldsa87": median(differences),
                "paired_blocks": len(size_blocks),
                "integer_evidence_preserved_before_ratio": metric == "signature_size_bytes",
            }
        output["message_sizes"][str(size)] = metrics
    return output


def selector_tls_cost_evidence(
    summary: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    gate: Mapping[str, Any],
    *,
    baseline_run_id: str,
    confirmatory_run_id: str,
    baseline_checksum: str,
    confirmatory_checksum: str,
    catalog_hash: str,
    scientific_design_hash: str,
) -> dict[str, Any]:
    profiles: list[dict[str, Any]] = []
    for profile in sorted(TLS_PROFILE_GROUPS):
        profiles.append(
            {
                "profile_id": profile,
                "tls_group": TLS_PROFILE_GROUPS[profile],
                "wall_time_relative_estimate": summary["wall_time_ns"][profile][
                    "final_relative_estimate"
                ],
                "wall_time_paired_bootstrap_interval": bootstrap[profile]["wall_time_ns"],
                "cpu_time_relative_estimate": summary["process_cpu_time_ns"][profile][
                    "final_relative_estimate"
                ],
                "cpu_time_paired_bootstrap_interval": bootstrap[profile][
                    "process_cpu_time_ns"
                ],
                "total_handshake_byte_relative_estimate": summary[
                    "total_handshake_bytes"
                ][profile]["final_relative_estimate"],
                "six_replicate_medians": {
                    "wall_time_ns": summary["wall_time_ns"][profile]["replicate_medians"],
                    "process_cpu_time_ns": summary["process_cpu_time_ns"][profile][
                        "replicate_medians"
                    ],
                    "total_handshake_bytes": summary["total_handshake_bytes"][profile][
                        "replicate_medians"
                    ],
                },
                "baseline_run_medians": {
                    "wall_time_ns": summary["wall_time_ns"][profile]["baseline_run_median"],
                    "process_cpu_time_ns": summary["process_cpu_time_ns"][profile][
                        "baseline_run_median"
                    ],
                    "total_handshake_bytes": summary["total_handshake_bytes"][profile][
                        "baseline_run_median"
                    ],
                },
                "confirmatory_run_medians": {
                    "wall_time_ns": summary["wall_time_ns"][profile]["confirmatory_run_median"],
                    "process_cpu_time_ns": summary["process_cpu_time_ns"][profile][
                        "confirmatory_run_median"
                    ],
                    "total_handshake_bytes": summary["total_handshake_bytes"][profile][
                        "confirmatory_run_median"
                    ],
                },
                "source_run_ids": [baseline_run_id, confirmatory_run_id],
                "source_raw_checksums": {
                    baseline_run_id: baseline_checksum,
                    confirmatory_run_id: confirmatory_checksum,
                },
                "catalog_hash": catalog_hash,
                "scientific_design_hash": scientific_design_hash,
                "usability_status": gate["profile_gates"][profile],
            }
        )
    return {
        "schema_version": 1,
        "artifact_type": "calibrated_tls_selector_cost_evidence",
        "policy_specific_cost_vector": False,
        "profiles": profiles,
    }


def _integrity(run_dir: Path, config: CryptoCalibrationConfig) -> dict[str, Any]:
    report = validate_raw_run(run_dir, config)
    if report["validation_passed"] is not True:
        raise ValueError(f"{run_dir.name}: raw integrity failed")
    return report


def _expected_blocks(config: CryptoCalibrationConfig) -> int:
    return 2 * len(config.replicates) * config.measured_blocks


def main() -> int:
    args = parse_args()
    if args.reference_profile != "P0":
        raise ValueError("Stage 3D currently supports only P0 as the reference profile")
    repo_root = Path(__file__).resolve().parents[1]
    raw_root = args.raw_root if args.raw_root.is_absolute() else repo_root / args.raw_root
    artifact_root = (
        args.artifact_root if args.artifact_root.is_absolute() else repo_root / args.artifact_root
    )
    output_dir = args.output_dir if args.output_dir.is_absolute() else repo_root / args.output_dir
    catalog_hash = validate_catalog_profile_mapping(repo_root, TLS_PROFILE_GROUPS)

    baseline_dir = raw_root / args.baseline_run_id
    confirmatory_dir = raw_root / args.confirmatory_run_id
    baseline_resolved = resolve_raw_run_config(baseline_dir)
    confirmatory_resolved = resolve_raw_run_config(confirmatory_dir)
    integrity = {
        "baseline": _integrity(baseline_dir, baseline_resolved.config),
        "confirmatory": _integrity(confirmatory_dir, confirmatory_resolved.config),
    }
    compatibility = compatibility_report_for_resolved(
        baseline_resolved,
        confirmatory_resolved,
        {
            "baseline": {"integrity_passed": True},
            "confirmatory": {"integrity_passed": True},
        },
    )
    if compatibility["comparison_compatible"] is not True:
        raise ValueError("baseline and confirmatory runs are not scientifically compatible")

    baseline_tls = pair_tls_blocks(args.baseline_run_id, baseline_dir, baseline_resolved.config)
    confirmatory_tls = pair_tls_blocks(
        args.confirmatory_run_id, confirmatory_dir, confirmatory_resolved.config
    )
    tls_blocks = [*baseline_tls, *confirmatory_tls]
    expected = _expected_blocks(baseline_resolved.config)
    if len(tls_blocks) != expected:
        raise ValueError(f"expected {expected} paired TLS blocks, observed {len(tls_blocks)}")
    tls_reciprocity = tls_reciprocity_diagnostics(tls_blocks)
    verify_reciprocal_consistency(tls_reciprocity)
    tls_rows = relative_tls_rows(tls_blocks, args.reference_profile)
    tls_summary = hierarchical_tls_summary(
        tls_rows, args.baseline_run_id, args.confirmatory_run_id
    )
    tls_bootstrap = tls_bootstrap_intervals(tls_blocks)
    absolute_stability = _absolute_timing_stability(
        artifact_root, [args.baseline_run_id, args.confirmatory_run_id]
    )
    gate = relative_quality_gate(
        tls_summary,
        tls_bootstrap,
        absolute_timing_stability=absolute_stability,
        compatibility_passed=bool(compatibility["comparison_compatible"]),
        complete_block_count=len(tls_blocks),
        expected_block_count=expected,
    )
    baseline_checksum = raw_run_checksum(baseline_dir)
    confirmatory_checksum = raw_run_checksum(confirmatory_dir)
    selector = selector_tls_cost_evidence(
        tls_summary,
        tls_bootstrap,
        gate,
        baseline_run_id=args.baseline_run_id,
        confirmatory_run_id=args.confirmatory_run_id,
        baseline_checksum=baseline_checksum,
        confirmatory_checksum=confirmatory_checksum,
        catalog_hash=catalog_hash,
        scientific_design_hash=baseline_resolved.scientific_design_hash,
    )
    mldsa_blocks = [
        *pair_mldsa_blocks(args.baseline_run_id, baseline_dir, baseline_resolved.config),
        *pair_mldsa_blocks(
            args.confirmatory_run_id, confirmatory_dir, confirmatory_resolved.config
        ),
    ]
    manifest = {
        "schema_version": 1,
        "baseline_run_id": args.baseline_run_id,
        "confirmatory_run_id": args.confirmatory_run_id,
        "reference_profile": args.reference_profile,
        "profile_mapping": TLS_PROFILE_GROUPS,
        "complete_tls_paired_blocks": len(tls_blocks),
        "expected_tls_paired_blocks": expected,
        "raw_runs_modified": False,
    }
    outputs = {
        "paired_dataset_manifest.json": manifest,
        "tls_relative_by_replicate.json": {
            "schema_version": 1,
            "rows": tls_rows,
        },
        "tls_relative_campaign_summary.json": {
            "schema_version": 1,
            "hierarchical_summary": tls_summary,
            "paired_bootstrap_intervals": tls_bootstrap,
        },
        "tls_pairwise_matrix.json": {
            "schema_version": 1,
            "reciprocity_diagnostics": tls_reciprocity,
            "ordered_profile_pairs": pairwise_tls_matrix(tls_blocks),
        },
        "mldsa_relative_summary.json": mldsa_relative_summary(mldsa_blocks),
        "selector_tls_cost_evidence.json": selector,
        "relative_cost_quality_gate.json": gate,
        "analysis_manifest.json": {
            "schema_version": 1,
            "analysis": "paired_block_normalized_crypto_costs",
            "generated_at_utc": utc_now(),
            "git_commit": git_commit(repo_root),
            "git_dirty": git_dirty(repo_root),
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
            "compatibility": compatibility,
            "integrity": integrity,
            "source_raw_checksums": {
                args.baseline_run_id: baseline_checksum,
                args.confirmatory_run_id: confirmatory_checksum,
            },
        },
    }
    with staged_report_dir(output_dir, replace_existing=bool(args.replace_existing)) as staging:
        written: list[Path] = []
        for name, payload in outputs.items():
            path = staging / name
            atomic_write_json(path, payload)
            written.append(path)
        write_checksums(staging, written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
