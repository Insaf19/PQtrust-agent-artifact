from __future__ import annotations

import hashlib
import json

import pytest

from pqtrust_agent.metrics.calibration_quality import (
    bootstrap_quality,
    machine_state_audit,
    relative_change,
    replicate_relative_range,
    robust_trend_for_replicate,
    same_direction_count,
    theil_sen_slope,
    windowed_drift_for_replicates,
)


def _records(values: list[float]) -> list[dict[str, float | int]]:
    return [{"block": index, "metric": value} for index, value in enumerate(values)]


def _digest_tree(path) -> dict[str, str]:
    return {
        item.relative_to(path).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(path.rglob("*"))
        if item.is_file()
    }


def test_windowed_drift_uses_first_and_last_20_blocks() -> None:
    report = windowed_drift_for_replicates(
        {
            "replicate-01": _records([100.0] * 180 + [120.0] * 20),
            "replicate-02": _records([100.0] * 180 + [121.0] * 20),
            "replicate-03": _records([100.0] * 180 + [122.0] * 20),
        },
        "metric",
    )

    assert report["replicates"]["replicate-01"]["first_window_median"] == 100.0
    assert report["replicates"]["replicate-01"]["last_window_median"] == 120.0
    assert report["campaign"]["same_direction_count"] == 3
    assert report["campaign"]["warning"] is True


def test_windowed_drift_rejects_insufficient_blocks() -> None:
    with pytest.raises(ValueError, match="requires blocks 0-199"):
        windowed_drift_for_replicates({"replicate-01": _records([1.0] * 199)}, "metric")


def test_relative_change_direction_and_warning_threshold() -> None:
    assert relative_change(100.0, 112.0) == 0.12
    assert same_direction_count([0.2, -0.3, -0.1]) == 2
    report = windowed_drift_for_replicates(
        {
            "replicate-01": _records([100.0] * 180 + [111.0] * 20),
            "replicate-02": _records([100.0] * 180 + [89.0] * 20),
            "replicate-03": _records([100.0] * 180 + [89.0] * 20),
        },
        "metric",
    )
    assert report["campaign"]["median_relative_change"] == -0.11
    assert report["campaign"]["negative_direction_count"] == 2
    assert report["campaign"]["warning"] is True


def test_theil_sen_slope_constant_increasing_and_decreasing() -> None:
    assert theil_sen_slope([(0.0, 5.0), (1.0, 5.0), (2.0, 5.0)]) == 0.0
    assert theil_sen_slope([(0.0, 1.0), (1.0, 3.0), (2.0, 5.0)]) == 2.0
    assert theil_sen_slope([(0.0, 5.0), (1.0, 3.0), (2.0, 1.0)]) == -2.0


def test_robust_trend_reports_normalized_expected_change_and_direction() -> None:
    report = robust_trend_for_replicate(_records([10.0, 12.0, 14.0, 16.0]), "metric")

    assert report["slope_per_block"] == 2.0
    assert report["normalized_slope_relative_to_replicate_median"] == pytest.approx(2.0 / 13.0)
    assert report["expected_relative_change_over_200_blocks"] == pytest.approx(8.0 / 13.0)
    assert report["direction"] == "positive"


def test_replicate_relative_range_threshold() -> None:
    report = replicate_relative_range([100.0, 105.0, 111.0])

    assert report["range"] == 11.0
    assert report["relative_replicate_range"] == pytest.approx(11.0 / 105.0)
    assert report["warning"] is True


def test_bootstrap_quality_relative_width_and_replicate_coverage() -> None:
    report = bootstrap_quality(
        {
            "case": {
                "metric": {
                    "campaign_median_of_replicate_medians": 100.0,
                    "replicate_medians": [95.0, 100.0, 105.0],
                    "hierarchical_bootstrap_95ci": {"lower": 90.0, "upper": 110.0},
                }
            }
        }
    )

    metric = report["case"]["metric"]
    assert metric["interval_width"] == 20.0
    assert metric["relative_interval_width"] == 0.2
    assert metric["interval_strictly_positive"] is True
    assert metric["all_replicate_medians_inside_interval"] is True


def test_machine_state_audit_preserves_nulls(tmp_path) -> None:
    run_dir = tmp_path / "run"
    replicate_dir = run_dir / "replicates" / "replicate-01"
    replicate_dir.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text('{"selected_cpu": 3}', encoding="utf-8")
    state = {
        "selected_cpu": 3,
        "process_affinity": [3],
        "load_averages": [1.0, 2.0, 3.0],
        "available_memory_kb": 1000,
        "cpu_scaling_governor": None,
        "cpu_scaling_frequency": None,
        "thermal_zone_temperatures": {},
    }
    for name in ("pre_state.json", "post_state.json"):
        (replicate_dir / name).write_text(__import__("json").dumps(state), encoding="utf-8")

    audit = machine_state_audit(run_dir)

    fields = audit["replicates"]["replicate-01"]["missing_value_fields"]
    assert "governor" in fields
    assert "frequency" in fields
    assert "thermal_values" in fields


def test_quality_readers_do_not_modify_raw_directory(tmp_path) -> None:
    from pqtrust_agent.metrics.calibration_quality import group_mldsa_records, group_tls_records

    run_dir = tmp_path / "run"
    replicate_dir = run_dir / "replicates" / "replicate-01"
    replicate_dir.mkdir(parents=True)
    (replicate_dir / "tls_handshakes.jsonl").write_text(
        json.dumps({"requested_group": "X25519", "block": 0}) + "\n",
        encoding="utf-8",
    )
    (replicate_dir / "mldsa.jsonl").write_text(
        json.dumps({"algorithm": "ML-DSA-65", "message_size_bytes": 512, "block": 0}) + "\n",
        encoding="utf-8",
    )
    before = _digest_tree(run_dir)

    assert group_tls_records(run_dir)["X25519"]["replicate-01"]
    assert group_mldsa_records(run_dir)["ML-DSA-65:512"]["replicate-01"]

    assert _digest_tree(run_dir) == before
