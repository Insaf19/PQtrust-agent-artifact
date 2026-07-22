from __future__ import annotations

from pqtrust_agent.assurance.order import (
    assurance_join,
    assurance_meet,
    comparable,
    dominates,
    strictly_dominates,
)
from pqtrust_agent.models import (
    FALLBACK_RULE_RANK,
    LEASE_STRICTNESS_RANK,
    RESUMPTION_RULE_RANK,
    AssuranceVector,
    FallbackRule,
    LeaseStrictness,
    ResumptionRule,
    ThreatClass,
)


def vector(
    *,
    key: frozenset[ThreatClass],
    auth: frozenset[ThreatClass],
    evidence: frozenset[ThreatClass],
    fallback: FallbackRule,
    resumption: ResumptionRule,
    lease: LeaseStrictness,
) -> AssuranceVector:
    return AssuranceVector(
        key_establishment_threats=key,
        endpoint_authentication_threats=auth,
        contract_evidence_threats=evidence,
        fallback_rule=fallback,
        resumption_rule=resumption,
        lease_strictness=lease,
    )


LOW = vector(
    key=frozenset({ThreatClass.CLASSICAL}),
    auth=frozenset({ThreatClass.CLASSICAL}),
    evidence=frozenset({ThreatClass.CLASSICAL}),
    fallback=FallbackRule.LOW_RISK_ONLY,
    resumption=ResumptionRule.CONTEXT_BOUND,
    lease=LeaseStrictness.LONG,
)
HIGH = vector(
    key=frozenset({ThreatClass.CLASSICAL, ThreatClass.QUANTUM}),
    auth=frozenset({ThreatClass.CLASSICAL}),
    evidence=frozenset({ThreatClass.CLASSICAL, ThreatClass.QUANTUM}),
    fallback=FallbackRule.FORBIDDEN,
    resumption=ResumptionRule.FORBIDDEN,
    lease=LeaseStrictness.SHORT,
)


def test_named_rank_mappings_are_explicit() -> None:
    assert FALLBACK_RULE_RANK == {
        FallbackRule.LOW_RISK_ONLY: 0,
        FallbackRule.EXPLICIT_ONLY: 1,
        FallbackRule.FORBIDDEN: 2,
    }
    assert RESUMPTION_RULE_RANK[ResumptionRule.CONTEXT_BOUND] < RESUMPTION_RULE_RANK[
        ResumptionRule.CONTRACT_BOUND
    ]
    assert LEASE_STRICTNESS_RANK[LeaseStrictness.LONG] < LEASE_STRICTNESS_RANK[
        LeaseStrictness.SHORT
    ]


def test_dominance_and_strict_dominance() -> None:
    assert dominates(LOW, LOW)
    assert dominates(HIGH, LOW)
    assert strictly_dominates(HIGH, LOW)
    assert not strictly_dominates(LOW, LOW)


def test_incomparable_assurance_vectors() -> None:
    left = vector(
        key=frozenset({ThreatClass.CLASSICAL, ThreatClass.QUANTUM}),
        auth=frozenset({ThreatClass.CLASSICAL}),
        evidence=frozenset({ThreatClass.CLASSICAL}),
        fallback=FallbackRule.LOW_RISK_ONLY,
        resumption=ResumptionRule.CONTEXT_BOUND,
        lease=LeaseStrictness.LONG,
    )
    right = vector(
        key=frozenset({ThreatClass.CLASSICAL}),
        auth=frozenset({ThreatClass.CLASSICAL}),
        evidence=frozenset({ThreatClass.CLASSICAL}),
        fallback=FallbackRule.FORBIDDEN,
        resumption=ResumptionRule.CONTEXT_BOUND,
        lease=LeaseStrictness.LONG,
    )

    assert not comparable(left, right)


def test_join_and_meet_for_incomparable_vectors() -> None:
    joined = assurance_join(LOW, HIGH)
    met = assurance_meet(LOW, HIGH)

    assert joined == HIGH
    assert met == LOW
    assert dominates(joined, LOW)
    assert dominates(joined, HIGH)
    assert dominates(LOW, met)
    assert dominates(HIGH, met)
