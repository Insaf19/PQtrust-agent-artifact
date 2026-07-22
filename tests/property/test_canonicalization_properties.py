from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pqtrust_agent.evidence.canonical import canonicalize

json_scalars = st.none() | st.booleans() | st.integers(
    min_value=-(2**53) + 1,
    max_value=(2**53) - 1,
) | st.text()
json_values = st.recursive(
    json_scalars,
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(min_size=1), children, max_size=4),
    max_leaves=12,
)


@given(st.dictionaries(st.text(min_size=1), json_values, min_size=1, max_size=8))
def test_canonicalization_is_independent_of_dict_insertion_order(
    data: dict[str, object],
) -> None:
    reversed_data = dict(reversed(tuple(data.items())))

    assert canonicalize(data) == canonicalize(reversed_data)


@given(st.sets(st.text(min_size=1), max_size=8))
def test_canonicalization_is_independent_of_set_order(values: set[str]) -> None:
    assert canonicalize({"values": values}) == canonicalize(
        {"values": set(reversed(tuple(values)))}
    )
