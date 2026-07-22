"""Partial order operations over assurance vectors."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

from pqtrust_agent.models.common import (
    FALLBACK_RULE_RANK,
    LEASE_STRICTNESS_RANK,
    RESUMPTION_RULE_RANK,
    AssuranceVector,
    FallbackRule,
    LeaseStrictness,
    ResumptionRule,
    ThreatClass,
)

Ranked = TypeVar("Ranked", FallbackRule, ResumptionRule, LeaseStrictness)


def _rank_dominates(left: Ranked, right: Ranked, ranks: Mapping[Ranked, int]) -> bool:
    return ranks[left] >= ranks[right]


def _rank_join(left: Ranked, right: Ranked, ranks: Mapping[Ranked, int]) -> Ranked:
    return left if ranks[left] >= ranks[right] else right


def _rank_meet(left: Ranked, right: Ranked, ranks: Mapping[Ranked, int]) -> Ranked:
    return left if ranks[left] <= ranks[right] else right


def dominates(left: AssuranceVector, right: AssuranceVector) -> bool:
    """Return true when ``left`` is component-wise at least as strong as ``right``."""

    return (
        left.key_establishment_threats.issuperset(right.key_establishment_threats)
        and left.endpoint_authentication_threats.issuperset(
            right.endpoint_authentication_threats
        )
        and left.contract_evidence_threats.issuperset(right.contract_evidence_threats)
        and _rank_dominates(left.fallback_rule, right.fallback_rule, FALLBACK_RULE_RANK)
        and _rank_dominates(
            left.resumption_rule,
            right.resumption_rule,
            RESUMPTION_RULE_RANK,
        )
        and _rank_dominates(
            left.lease_strictness,
            right.lease_strictness,
            LEASE_STRICTNESS_RANK,
        )
    )


def strictly_dominates(left: AssuranceVector, right: AssuranceVector) -> bool:
    """Return true when ``left`` dominates ``right`` and the vectors differ."""

    return left != right and dominates(left, right)


def comparable(left: AssuranceVector, right: AssuranceVector) -> bool:
    """Return true when either vector dominates the other."""

    return dominates(left, right) or dominates(right, left)


def assurance_join(left: AssuranceVector, right: AssuranceVector) -> AssuranceVector:
    """Return the least upper bound of two assurance vectors."""

    return AssuranceVector(
        key_establishment_threats=frozenset(
            left.key_establishment_threats | right.key_establishment_threats
        ),
        endpoint_authentication_threats=frozenset(
            left.endpoint_authentication_threats | right.endpoint_authentication_threats
        ),
        contract_evidence_threats=frozenset(
            left.contract_evidence_threats | right.contract_evidence_threats
        ),
        fallback_rule=_rank_join(left.fallback_rule, right.fallback_rule, FALLBACK_RULE_RANK),
        resumption_rule=_rank_join(
            left.resumption_rule,
            right.resumption_rule,
            RESUMPTION_RULE_RANK,
        ),
        lease_strictness=_rank_join(
            left.lease_strictness,
            right.lease_strictness,
            LEASE_STRICTNESS_RANK,
        ),
    )


def assurance_meet(left: AssuranceVector, right: AssuranceVector) -> AssuranceVector:
    """Return the greatest lower bound of two assurance vectors."""

    return AssuranceVector(
        key_establishment_threats=frozenset(
            left.key_establishment_threats & right.key_establishment_threats
        ),
        endpoint_authentication_threats=frozenset(
            left.endpoint_authentication_threats & right.endpoint_authentication_threats
        ),
        contract_evidence_threats=frozenset(
            left.contract_evidence_threats & right.contract_evidence_threats
        ),
        fallback_rule=_rank_meet(left.fallback_rule, right.fallback_rule, FALLBACK_RULE_RANK),
        resumption_rule=_rank_meet(
            left.resumption_rule,
            right.resumption_rule,
            RESUMPTION_RULE_RANK,
        ),
        lease_strictness=_rank_meet(
            left.lease_strictness,
            right.lease_strictness,
            LEASE_STRICTNESS_RANK,
        ),
    )


def all_threats() -> frozenset[ThreatClass]:
    """Return the complete threat-class set for test generation and schemas."""

    return frozenset(ThreatClass)
