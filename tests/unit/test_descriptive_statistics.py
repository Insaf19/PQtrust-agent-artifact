from __future__ import annotations

import math

from pqtrust_agent.metrics.descriptive import (
    describe,
    drift_report,
    identical_value_report,
    mad,
    median,
    outlier_count_3mad,
    quantile,
    replicate_median_summary,
    sample_standard_deviation,
)


def test_median_quantiles_sample_stdev_and_mad_are_deterministic() -> None:
    values = [1, 2, 3, 4]

    assert median(values) == 2.5
    assert quantile(values, 0.25) == 1.75
    assert math.isclose(sample_standard_deviation(values), 1.2909944487358056)
    assert mad(values) == 1.0
    assert describe(values)["p95"] == 3.8499999999999996


def test_one_observation_and_constant_distribution_edges() -> None:
    assert describe([7])["sample_standard_deviation"] == 0.0
    assert quantile([7], 0.99) == 7.0
    assert identical_value_report([5, 5, 5]) == {
        "all_observations_identical": True,
        "value": 5.0,
        "minimum": 5.0,
        "maximum": 5.0,
    }


def test_hierarchical_aggregation_uses_replicate_medians() -> None:
    summary = replicate_median_summary([[1, 100, 1000], [2, 3, 4], [10, 11, 12]])

    assert summary["replicate_medians"] == [100.0, 3.0, 11.0]
    assert summary["campaign_median_of_replicate_medians"] == 11.0


def test_zero_mad_does_not_delete_outliers() -> None:
    report = outlier_count_3mad([10, 10, 10, 99])

    assert report["method_status"] == "undefined_zero_mad"
    assert report["count"] is None
    assert report["proportion"] is None
    assert report["distinct_value_count"] == 2
    assert report["range"] == 89.0


def test_non_zero_mad_reports_outlier_count_without_deletion() -> None:
    values = [10, 11, 12, 13, 100]
    report = outlier_count_3mad(values)

    assert report["method_status"] == "defined"
    assert report["count"] == 1
    assert report["proportion"] == 0.2
    assert len(values) == 5


def test_drift_and_instability_warning_thresholds() -> None:
    records = [
        {"block": 0, "metric": 100},
        {"block": 0, "metric": 100},
        {"block": 1, "metric": 112},
        {"block": 1, "metric": 112},
    ]

    report = drift_report(records, "metric", [100, 100, 112])

    assert report["drift_warning"] is True
    assert report["replicate_instability_warning"] is True
