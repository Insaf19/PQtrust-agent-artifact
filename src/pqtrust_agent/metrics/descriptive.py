"""Standard-library descriptive statistics for calibration evidence."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any

QUANTILE_DEFINITION = "linear interpolation between closest ranks using h=(n-1)*p+1"


def _sorted(values: Iterable[float]) -> list[float]:
    result = sorted(float(value) for value in values)
    if not result:
        raise ValueError("statistics require at least one observation")
    if any(not math.isfinite(value) for value in result):
        raise ValueError("statistics reject NaN and infinity")
    return result


def median(values: Iterable[float]) -> float:
    ordered = _sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def quantile(values: Iterable[float], probability: float) -> float:
    if not 0 <= probability <= 1:
        raise ValueError("probability must be in [0, 1]")
    ordered = _sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def sample_standard_deviation(values: Iterable[float]) -> float:
    observed = [float(value) for value in values]
    if not observed:
        raise ValueError("statistics require at least one observation")
    if any(not math.isfinite(value) for value in observed):
        raise ValueError("statistics reject NaN and infinity")
    if len(observed) == 1:
        return 0.0
    mean = sum(observed) / len(observed)
    variance = sum((value - mean) ** 2 for value in observed) / (len(observed) - 1)
    return math.sqrt(variance)


def mad(values: Iterable[float]) -> float:
    observed = [float(value) for value in values]
    center = median(observed)
    return median(abs(value - center) for value in observed)


def describe(values: Sequence[float]) -> dict[str, float | int]:
    observed = [float(value) for value in values]
    ordered = _sorted(observed)
    return {
        "count": len(ordered),
        "minimum": ordered[0],
        "maximum": ordered[-1],
        "mean": sum(ordered) / len(ordered),
        "median": median(ordered),
        "sample_standard_deviation": sample_standard_deviation(ordered),
        "mad": mad(ordered),
        "p05": quantile(ordered, 0.05),
        "p25": quantile(ordered, 0.25),
        "p75": quantile(ordered, 0.75),
        "p95": quantile(ordered, 0.95),
        "p99": quantile(ordered, 0.99),
    }


def replicate_median_summary(replicate_values: Sequence[Sequence[float]]) -> dict[str, Any]:
    medians = [median(values) for values in replicate_values]
    center = median(medians)
    return {
        "campaign_median_of_replicate_medians": center,
        "minimum_replicate_median": min(medians),
        "maximum_replicate_median": max(medians),
        "between_replicate_range": max(medians) - min(medians),
        "replicate_medians": medians,
    }


def identical_value_report(values: Sequence[float]) -> dict[str, Any]:
    ordered = _sorted(values)
    first = ordered[0]
    identical = all(value == first for value in ordered)
    return {
        "all_observations_identical": identical,
        "value": first if identical else None,
        "minimum": ordered[0],
        "maximum": ordered[-1],
    }


def outlier_count_3mad(values: Sequence[float]) -> dict[str, float | int | str | None]:
    observed = [float(value) for value in values]
    center = median(observed)
    spread = mad(observed)
    if spread == 0:
        ordered = _sorted(observed)
        return {
            "method_status": "undefined_zero_mad",
            "count": None,
            "proportion": None,
            "distinct_value_count": len(set(ordered)),
            "minimum": ordered[0],
            "maximum": ordered[-1],
            "range": ordered[-1] - ordered[0],
        }
    count = sum(1 for value in observed if abs(value - center) > 3 * spread)
    return {
        "method_status": "defined",
        "count": count,
        "proportion": count / len(observed),
    }


def drift_report(
    records: Sequence[dict[str, Any]],
    metric: str,
    replicate_medians: Sequence[float],
) -> dict[str, Any]:
    blocks = sorted({int(record["block"]) for record in records})
    first_block = blocks[0]
    last_block = blocks[-1]
    first_median = median(
        float(record[metric]) for record in records if record["block"] == first_block
    )
    last_median = median(
        float(record[metric]) for record in records if record["block"] == last_block
    )
    relative_change = 0.0 if first_median == 0 else (last_median - first_median) / first_median
    replicate_center = median(replicate_medians)
    replicate_range = max(replicate_medians) - min(replicate_medians)
    instability = 0.0 if replicate_center == 0 else replicate_range / replicate_center
    return {
        "first_block_median": first_median,
        "last_block_median": last_median,
        "relative_first_to_last_median_change": relative_change,
        "drift_warning": abs(relative_change) > 0.10,
        "replicate_to_replicate_median_range": replicate_range,
        "replicate_instability_ratio": instability,
        "replicate_instability_warning": instability > 0.10,
    }
