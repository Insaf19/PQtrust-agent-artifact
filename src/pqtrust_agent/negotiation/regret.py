"""Weighted costs, regret tables, and minimax-regret tie-breaking."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from pqtrust_agent.models.preference import AgentCostPreference
from pqtrust_agent.negotiation.cost_evidence import METRICS, MetricName

BPS_DENOMINATOR = Decimal(10000)


@dataclass(frozen=True)
class WeightedCost:
    components: dict[MetricName, Decimal]
    total: Decimal


def weighted_cost(
    normalized: dict[MetricName, Decimal],
    preference: AgentCostPreference,
) -> WeightedCost:
    """Compute exact weighted normalized cost with integer basis-point weights."""

    weights: dict[MetricName, int] = {
        "wall_time": preference.wall_time_weight_bps,
        "process_cpu_time": preference.process_cpu_time_weight_bps,
        "total_handshake_bytes": preference.total_handshake_bytes_weight_bps,
    }
    components = {
        metric: (Decimal(weights[metric]) / BPS_DENOMINATOR) * normalized[metric]
        for metric in METRICS
    }
    return WeightedCost(components=components, total=sum(components.values(), Decimal(0)))


@dataclass(frozen=True)
class RegretRow:
    profile_id: str
    initiator_cost: WeightedCost
    responder_cost: WeightedCost
    initiator_regret: Decimal
    responder_regret: Decimal
    maximum_regret: Decimal
    total_regret: Decimal
    maximum_normalized_component: Decimal
    total_normalized_cost: Decimal


def compute_regret_rows(
    profile_ids: tuple[str, ...],
    normalized_vectors: dict[str, dict[MetricName, Decimal]],
    initiator: AgentCostPreference,
    responder: AgentCostPreference,
) -> tuple[RegretRow, ...]:
    """Compute candidate costs and bilateral regrets."""

    weighted: dict[str, tuple[WeightedCost, WeightedCost]] = {
        profile_id: (
            weighted_cost(normalized_vectors[profile_id], initiator),
            weighted_cost(normalized_vectors[profile_id], responder),
        )
        for profile_id in profile_ids
    }
    min_initiator = min(item[0].total for item in weighted.values())
    min_responder = min(item[1].total for item in weighted.values())
    rows: list[RegretRow] = []
    for profile_id in profile_ids:
        initiator_cost, responder_cost = weighted[profile_id]
        initiator_regret = initiator_cost.total - min_initiator
        responder_regret = responder_cost.total - min_responder
        if initiator_regret < 0 or responder_regret < 0:
            raise ValueError("regret must be non-negative")
        normalized = normalized_vectors[profile_id]
        rows.append(
            RegretRow(
                profile_id=profile_id,
                initiator_cost=initiator_cost,
                responder_cost=responder_cost,
                initiator_regret=initiator_regret,
                responder_regret=responder_regret,
                maximum_regret=max(initiator_regret, responder_regret),
                total_regret=initiator_regret + responder_regret,
                maximum_normalized_component=max(normalized.values()),
                total_normalized_cost=sum(normalized.values(), Decimal(0)),
            )
        )
    no_zero_initiator = all(row.initiator_regret != 0 for row in rows)
    no_zero_responder = all(row.responder_regret != 0 for row in rows)
    if no_zero_initiator or no_zero_responder:
        raise ValueError("each agent must have at least one zero-regret profile")
    return tuple(rows)


def minimax_regret_select(rows: tuple[RegretRow, ...]) -> tuple[str, tuple[str, ...]]:
    """Select the minimax-regret row using the required deterministic lexicographic key."""

    if not rows:
        raise ValueError("cannot select from an empty candidate set")
    keys = {
        row.profile_id: (
            row.maximum_regret,
            row.total_regret,
            row.maximum_normalized_component,
            row.total_normalized_cost,
            row.profile_id,
        )
        for row in rows
    }
    ordered = sorted(rows, key=lambda row: keys[row.profile_id])
    selected = ordered[0].profile_id
    trace = [
        "tie_break_order=max_regret,total_regret,max_normalized_component,total_normalized_cost,profile_id"
    ]
    for row in ordered:
        trace.append(f"{row.profile_id}: {keys[row.profile_id]}")
    trace.append(f"selected={selected}")
    return selected, tuple(trace)
