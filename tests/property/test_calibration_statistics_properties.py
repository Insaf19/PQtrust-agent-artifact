from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pqtrust_agent.metrics.descriptive import median, quantile


@given(st.lists(st.integers(min_value=-10_000, max_value=10_000), min_size=1, max_size=50))
def test_median_lies_between_minimum_and_maximum(values: list[int]) -> None:
    result = median(values)

    assert min(values) <= result <= max(values)


@given(st.lists(st.integers(min_value=-10_000, max_value=10_000), min_size=1, max_size=50))
def test_documented_quantiles_are_monotonic(values: list[int]) -> None:
    assert quantile(values, 0.05) <= quantile(values, 0.50) <= quantile(values, 0.95)
