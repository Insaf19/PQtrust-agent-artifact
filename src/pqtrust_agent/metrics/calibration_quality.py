"""Stage 3C calibration-quality diagnostics."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from pqtrust_agent.metrics.descriptive import median, outlier_count_3mad
from pqtrust_agent.metrics.validation import load_json, load_jsonl

TIMING_STABILITY_THRESHOLD = 0.10
WINDOW_SIZE_BLOCKS = 20
FIRST_WINDOW = tuple(range(0, 20))
LAST_WINDOW = tuple(range(180, 200))

TLS_METRICS = (
    "wall_time_ns",
    "process_cpu_time_ns",
    "client_to_server_bytes",
    "server_to_client_bytes",
    "total_handshake_bytes",
)
TLS_TIMING_METRICS = ("wall_time_ns", "process_cpu_time_ns")
MLDSA_METRICS = ("sign_time_ns", "verify_time_ns", "signature_size_bytes")
MLDSA_TIMING_METRICS = ("sign_time_ns", "verify_time_ns")


def group_tls_records(run_dir: Path) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for replicate_dir in sorted((run_dir / "replicates").iterdir()):
        if not replicate_dir.is_dir():
            continue
        for record in load_jsonl(replicate_dir / "tls_handshakes.jsonl"):
            grouped[str(record["requested_group"])][replicate_dir.name].append(record)
    return {case: dict(replicates) for case, replicates in grouped.items()}


def group_mldsa_records(run_dir: Path) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for replicate_dir in sorted((run_dir / "replicates").iterdir()):
        if not replicate_dir.is_dir():
            continue
        for record in load_jsonl(replicate_dir / "mldsa.jsonl"):
            case = f"{record['algorithm']}:{record['message_size_bytes']}"
            grouped[case][replicate_dir.name].append(record)
    return {case: dict(replicates) for case, replicates in grouped.items()}


def relative_change(first: float, last: float) -> float:
    if first == 0:
        raise ValueError("relative change is undefined when first value is zero")
    return (last - first) / first


def direction(value: float) -> str:
    if value > 0:
        return "positive"
    if value < 0:
        return "negative"
    return "zero"


def same_direction_count(changes: Sequence[float]) -> int:
    positives = sum(1 for change in changes if change > 0)
    negatives = sum(1 for change in changes if change < 0)
    return max(positives, negatives)


def replicate_relative_range(values: Sequence[float]) -> dict[str, Any]:
    med = median(values)
    spread = max(values) - min(values)
    relative = 0.0 if med == 0 else spread / med
    return {
        "replicate_medians": list(values),
        "minimum": min(values),
        "maximum": max(values),
        "range": spread,
        "median_of_replicate_medians": med,
        "relative_replicate_range": relative,
        "warning": relative > TIMING_STABILITY_THRESHOLD,
    }


def _block_values(records: Sequence[dict[str, Any]], metric: str) -> dict[int, list[float]]:
    values: dict[int, list[float]] = defaultdict(list)
    for record in records:
        values[int(record["block"])].append(float(record[metric]))
    return dict(values)


def _window_median(block_values: Mapping[int, Sequence[float]], blocks: Sequence[int]) -> float:
    missing = [block for block in blocks if block not in block_values]
    if missing:
        raise ValueError(f"insufficient blocks for window; missing {missing[:5]}")
    values = [value for block in blocks for value in block_values[block]]
    return median(values)


def windowed_drift_for_replicates(
    replicates: Mapping[str, Sequence[dict[str, Any]]],
    metric: str,
) -> dict[str, Any]:
    replicate_results: dict[str, Any] = {}
    changes: list[float] = []
    for replicate, records in sorted(replicates.items()):
        blocks = _block_values(records, metric)
        if len(blocks) < max(LAST_WINDOW) + 1:
            raise ValueError("windowed drift requires blocks 0-199")
        first = _window_median(blocks, FIRST_WINDOW)
        last = _window_median(blocks, LAST_WINDOW)
        change = relative_change(first, last)
        changes.append(change)
        replicate_results[replicate] = {
            "first_window_blocks": [FIRST_WINDOW[0], FIRST_WINDOW[-1]],
            "last_window_blocks": [LAST_WINDOW[0], LAST_WINDOW[-1]],
            "first_window_median": first,
            "last_window_median": last,
            "relative_change": change,
            "direction": direction(change),
        }
    median_change = median(changes)
    positives = sum(1 for change in changes if change > 0)
    negatives = sum(1 for change in changes if change < 0)
    agreement = same_direction_count(changes)
    return {
        "replicates": replicate_results,
        "campaign": {
            "median_relative_change": median_change,
            "minimum_relative_change": min(changes),
            "maximum_relative_change": max(changes),
            "positive_direction_count": positives,
            "negative_direction_count": negatives,
            "same_direction_count": agreement,
            "warning": (
                abs(median_change) > TIMING_STABILITY_THRESHOLD and agreement >= 2
            ),
        },
    }


def theil_sen_slope(points: Sequence[tuple[float, float]]) -> float:
    slopes: list[float] = []
    for left_index, (left_x, left_y) in enumerate(points):
        for right_x, right_y in points[left_index + 1 :]:
            if right_x != left_x:
                slopes.append((right_y - left_y) / (right_x - left_x))
    if not slopes:
        return 0.0
    return median(slopes)


def robust_trend_for_replicate(records: Sequence[dict[str, Any]], metric: str) -> dict[str, Any]:
    by_block = _block_values(records, metric)
    points = [(float(block), median(values)) for block, values in sorted(by_block.items())]
    slope = theil_sen_slope(points)
    replicate_median = median(value for _block, value in points)
    normalized = 0.0 if replicate_median == 0 else slope / replicate_median
    expected = normalized * len(points)
    return {
        "slope_per_block": slope,
        "normalized_slope_relative_to_replicate_median": normalized,
        "expected_relative_change_over_200_blocks": expected,
        "direction": direction(slope),
    }


def outlier_diagnostics(
    grouped: Mapping[str, Mapping[str, Sequence[dict[str, Any]]]],
    metrics: Iterable[str],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for metric in metrics:
            values = [
                float(record[metric])
                for records in replicates.values()
                for record in records
            ]
            report = dict(outlier_count_3mad(values))
            report["descriptive_only"] = True
            report["observations_deleted"] = 0
            output[case][metric] = report
    return output


def replicate_stability(
    grouped: Mapping[str, Mapping[str, Sequence[dict[str, Any]]]],
    metrics: Iterable[str],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for metric in metrics:
            medians = [
                median(float(record[metric]) for record in records)
                for _replicate, records in sorted(replicates.items())
            ]
            output[case][metric] = replicate_relative_range(medians)
    return output


def windowed_drift(
    grouped: Mapping[str, Mapping[str, Sequence[dict[str, Any]]]],
    metrics: Iterable[str],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for metric in metrics:
            output[case][metric] = windowed_drift_for_replicates(replicates, metric)
    return output


def robust_trend(
    grouped: Mapping[str, Mapping[str, Sequence[dict[str, Any]]]],
    timing_metrics: Iterable[str],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for metric in timing_metrics:
            output[case][metric] = {
                replicate: robust_trend_for_replicate(records, metric)
                for replicate, records in sorted(replicates.items())
            }
    return output


def bootstrap_quality(summary: Mapping[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, metrics in summary.items():
        output[case] = {}
        for metric, metric_summary in metrics.items():
            ci = metric_summary["hierarchical_bootstrap_95ci"]
            campaign_median = float(metric_summary["campaign_median_of_replicate_medians"])
            lower = float(ci["lower"])
            upper = float(ci["upper"])
            width = upper - lower
            output[case][metric] = {
                "campaign_median": campaign_median,
                "confidence_interval": ci,
                "interval_width": width,
                "relative_interval_width": (
                    0.0 if campaign_median == 0 else width / campaign_median
                ),
                "interval_strictly_positive": lower > 0 and upper > 0,
                "all_replicate_medians_inside_interval": all(
                    lower <= float(value) <= upper
                    for value in metric_summary["replicate_medians"]
                ),
            }
    return output


def _field_change(pre: Mapping[str, Any], post: Mapping[str, Any], field: str) -> dict[str, Any]:
    return {
        "pre": pre.get(field),
        "post": post.get(field),
        "changed": pre.get(field) != post.get(field),
    }


def machine_state_audit(run_dir: Path) -> dict[str, Any]:
    manifest = load_json(run_dir / "run_manifest.json")
    replicates: dict[str, Any] = {}
    for replicate_dir in sorted((run_dir / "replicates").iterdir()):
        if not replicate_dir.is_dir():
            continue
        pre = load_json(replicate_dir / "pre_state.json")
        post = load_json(replicate_dir / "post_state.json")
        fields = {
            "selected_cpu": _field_change(pre, post, "selected_cpu"),
            "applied_affinity": _field_change(pre, post, "process_affinity"),
            "load_averages": _field_change(pre, post, "load_averages"),
            "available_memory_kb": _field_change(pre, post, "available_memory_kb"),
            "governor": _field_change(pre, post, "cpu_scaling_governor"),
            "frequency": _field_change(pre, post, "cpu_scaling_frequency"),
            "thermal_values": _field_change(pre, post, "thermal_zone_temperatures"),
        }
        missing = [
            name
            for name, change in fields.items()
            if change["pre"] in (None, {}) or change["post"] in (None, {})
        ]
        replicates[replicate_dir.name] = {
            **fields,
            "missing_value_fields": missing,
        }
    return {
        "schema_version": 1,
        "raw_run": run_dir.name,
        "selected_cpu": manifest.get("selected_cpu"),
        "causality_claimed": False,
        "replicates": replicates,
    }


def any_warning(report: Mapping[str, Any], warning_key: str = "warning") -> bool:
    if warning_key in report and report[warning_key] is True:
        return True
    return any(
        any_warning(value, warning_key) for value in report.values() if isinstance(value, dict)
    )
