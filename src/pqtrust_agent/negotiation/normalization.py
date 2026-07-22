"""Global fixed normalization for measured selector costs."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from pqtrust_agent.negotiation.cost_evidence import METRICS, MetricName, ProfileCostEvidence


@dataclass(frozen=True)
class NormalizationAnchors:
    minima: dict[MetricName, Decimal]
    maxima: dict[MetricName, Decimal]

    def as_dict(self) -> dict[str, dict[str, Decimal]]:
        return {
            "minima": {str(key): value for key, value in self.minima.items()},
            "maxima": {str(key): value for key, value in self.maxima.items()},
        }


def compute_global_anchors(
    profiles: tuple[ProfileCostEvidence, ...],
    *,
    case: str = "point",
) -> NormalizationAnchors:
    """Compute global P0-P4 min/max anchors for one uncertainty case."""

    minima: dict[MetricName, Decimal] = {}
    maxima: dict[MetricName, Decimal] = {}
    for metric in METRICS:
        values = [profile.measured_vector(case)[metric] for profile in profiles]
        minimum = min(values)
        maximum = max(values)
        if maximum == minimum:
            raise ValueError(f"normalization denominator is zero for {metric}")
        minima[metric] = minimum
        maxima[metric] = maximum
    return NormalizationAnchors(minima=minima, maxima=maxima)


def normalize_vector(
    raw: dict[MetricName, Decimal],
    anchors: NormalizationAnchors,
) -> dict[MetricName, Decimal]:
    """Normalize one raw measured vector using fixed global anchors."""

    normalized: dict[MetricName, Decimal] = {}
    for metric in METRICS:
        value = (raw[metric] - anchors.minima[metric]) / (
            anchors.maxima[metric] - anchors.minima[metric]
        )
        if value < 0 or value > 1:
            raise ValueError(f"normalized {metric} is outside [0,1]")
        normalized[metric] = value
    return normalized
