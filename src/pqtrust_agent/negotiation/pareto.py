"""Cost Pareto filtering over raw measured cost vectors."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from pqtrust_agent.negotiation.cost_evidence import METRICS, MetricName


@dataclass(frozen=True)
class DominationExplanation:
    profile_id: str
    dominating_profile_ids: tuple[str, ...]
    dominated_dimensions: dict[str, tuple[str, ...]]
    measured_values: dict[str, dict[MetricName, Decimal]]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "dominating_profile_ids": list(self.dominating_profile_ids),
            "dominated_dimensions": {
                key: list(value) for key, value in self.dominated_dimensions.items()
            },
            "measured_values": self.measured_values,
        }


def dominates(
    left: dict[MetricName, Decimal],
    right: dict[MetricName, Decimal],
) -> tuple[bool, tuple[str, ...]]:
    """Return whether left cost-dominates right and which dimensions are strict."""

    strict: list[str] = []
    for metric in METRICS:
        if left[metric] > right[metric]:
            return False, ()
        if left[metric] < right[metric]:
            strict.append(metric)
    return bool(strict), tuple(strict)


def pareto_filter(
    profile_ids: tuple[str, ...],
    raw_vectors: dict[str, dict[MetricName, Decimal]],
) -> tuple[tuple[str, ...], dict[str, DominationExplanation]]:
    """Return deterministic Pareto frontier and dominated-profile explanations."""

    removed: dict[str, DominationExplanation] = {}
    for profile_id in profile_ids:
        dominators: list[str] = []
        strict_by_dominator: dict[str, tuple[str, ...]] = {}
        measured: dict[str, dict[MetricName, Decimal]] = {profile_id: raw_vectors[profile_id]}
        for other_id in profile_ids:
            if other_id == profile_id:
                continue
            is_dominated, strict = dominates(raw_vectors[other_id], raw_vectors[profile_id])
            if is_dominated:
                dominators.append(other_id)
                strict_by_dominator[other_id] = strict
                measured[other_id] = raw_vectors[other_id]
        if dominators:
            removed[profile_id] = DominationExplanation(
                profile_id=profile_id,
                dominating_profile_ids=tuple(sorted(dominators)),
                dominated_dimensions={key: strict_by_dominator[key] for key in sorted(dominators)},
                measured_values={key: measured[key] for key in sorted(measured)},
            )
    frontier = tuple(profile_id for profile_id in profile_ids if profile_id not in removed)
    return frontier, dict(sorted(removed.items()))

