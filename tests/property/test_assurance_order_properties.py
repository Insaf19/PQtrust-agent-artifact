from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pqtrust_agent.assurance.order import (
    assurance_join,
    assurance_meet,
    dominates,
    strictly_dominates,
)
from pqtrust_agent.models import (
    AssuranceVector,
    FallbackRule,
    LeaseStrictness,
    ResumptionRule,
    ThreatClass,
)


def threat_sets() -> st.SearchStrategy[frozenset[ThreatClass]]:
    return st.sets(st.sampled_from(tuple(ThreatClass)), max_size=2).map(frozenset)


@st.composite
def assurance_vectors(draw: st.DrawFn) -> AssuranceVector:
    return AssuranceVector(
        key_establishment_threats=draw(threat_sets()),
        endpoint_authentication_threats=draw(threat_sets()),
        contract_evidence_threats=draw(threat_sets()),
        fallback_rule=draw(st.sampled_from(tuple(FallbackRule))),
        resumption_rule=draw(st.sampled_from(tuple(ResumptionRule))),
        lease_strictness=draw(st.sampled_from(tuple(LeaseStrictness))),
    )


@given(assurance_vectors())
def test_dominance_reflexivity(vector: AssuranceVector) -> None:
    assert dominates(vector, vector)


@given(assurance_vectors(), assurance_vectors(), assurance_vectors())
def test_dominance_transitivity(
    left: AssuranceVector,
    middle: AssuranceVector,
    right: AssuranceVector,
) -> None:
    if dominates(left, middle) and dominates(middle, right):
        assert dominates(left, right)


@given(assurance_vectors())
def test_strict_dominance_irreflexivity(vector: AssuranceVector) -> None:
    assert not strictly_dominates(vector, vector)


@given(assurance_vectors(), assurance_vectors())
def test_join_and_meet_laws(left: AssuranceVector, right: AssuranceVector) -> None:
    joined = assurance_join(left, right)
    met = assurance_meet(left, right)

    assert dominates(joined, left)
    assert dominates(joined, right)
    assert dominates(left, met)
    assert dominates(right, met)
    assert assurance_join(left, left) == left
    assert assurance_meet(right, right) == right
