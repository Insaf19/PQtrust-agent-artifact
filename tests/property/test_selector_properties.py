"""Property tests for selector cost ordering invariants."""

from __future__ import annotations

from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st

from pqtrust_agent.negotiation.pareto import dominates
from pqtrust_agent.negotiation.sensitivity import weight_grid


@given(
    st.decimals(min_value="0", max_value="100", allow_nan=False, allow_infinity=False),
    st.decimals(min_value="0", max_value="100", allow_nan=False, allow_infinity=False),
    st.decimals(min_value="0", max_value="100", allow_nan=False, allow_infinity=False),
)
def test_identical_vectors_are_incomparable(wall: Decimal, cpu: Decimal, bytes_: Decimal) -> None:
    vector = {
        "wall_time": wall,
        "process_cpu_time": cpu,
        "total_handshake_bytes": bytes_,
    }
    assert dominates(vector, vector) == (False, ())


def test_weight_grid_is_byte_stable() -> None:
    assert weight_grid() == weight_grid()

