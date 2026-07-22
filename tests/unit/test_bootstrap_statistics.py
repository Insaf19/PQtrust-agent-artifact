from __future__ import annotations

from pqtrust_agent.metrics.bootstrap import hierarchical_bootstrap_median_ci


def test_hierarchical_bootstrap_is_reproducible() -> None:
    values = [[1, 2, 3], [10, 11, 12], [20, 21, 22]]

    first = hierarchical_bootstrap_median_ci(values, iterations=200, seed=20260801)
    second = hierarchical_bootstrap_median_ci(values, iterations=200, seed=20260801)

    assert first == second
    assert first["lower"] <= first["upper"]


def test_hierarchical_bootstrap_constant_distribution() -> None:
    report = hierarchical_bootstrap_median_ci([[5, 5], [5, 5], [5, 5]], iterations=50)

    assert report["lower"] == 5.0
    assert report["upper"] == 5.0
