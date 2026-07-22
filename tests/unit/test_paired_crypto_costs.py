from __future__ import annotations

import json
import math
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

from pqtrust_agent.metrics.calibration_models import load_calibration_config

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = spec_from_file_location(
    "analyze_paired_crypto_costs", REPO_ROOT / "scripts/analyze_paired_crypto_costs.py"
)
assert SPEC is not None and SPEC.loader is not None
PAIRED = module_from_spec(SPEC)
sys.modules[SPEC.name] = PAIRED
SPEC.loader.exec_module(PAIRED)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def _tls_row(
    sequence: int,
    block: int,
    group: str,
    *,
    success: bool = True,
) -> dict[str, object]:
    profile_index = list(PAIRED.TLS_PROFILE_GROUPS.values()).index(group)
    base = 1000 + block
    return {
        "sequence": sequence,
        "block": block,
        "position_in_block": 99 - profile_index,
        "requested_group": group,
        "wall_time_ns": base * (profile_index + 1),
        "process_cpu_time_ns": (base + 10) * (profile_index + 1),
        "client_to_server_bytes": 100 + profile_index,
        "server_to_client_bytes": 200 + profile_index,
        "total_handshake_bytes": 300 + profile_index,
        "success": success,
    }


def _raw_tls_fixture(tmp_path: Path, *, mutate: str | None = None) -> Path:
    run_dir = tmp_path / "raw" / "fixture-run"
    sequence = 0
    for replicate in range(1, 4):
        rows: list[dict[str, object]] = []
        for block in range(200):
            groups = list(reversed(PAIRED.TLS_PROFILE_GROUPS.values()))
            for group in groups:
                rows.append(_tls_row(sequence, block, group))
                sequence += 1
        if mutate == "missing" and replicate == 1:
            rows = [
                row
                for row in rows
                if not (row["block"] == 0 and row["requested_group"] == "MLKEM768")
            ]
        if mutate == "duplicate" and replicate == 1:
            rows.append(_tls_row(sequence, 0, "X25519"))
        if mutate == "failed" and replicate == 1:
            rows[0]["success"] = False
        _write_jsonl(
            run_dir / "replicates" / f"replicate-{replicate:02d}" / "tls_handshakes.jsonl",
            rows,
        )
    return run_dir


def _config():
    return load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")


def _toy_blocks() -> list[object]:
    blocks = []
    for run_id in ("baseline", "confirmatory"):
        for replicate in range(1, 4):
            for block in range(3):
                records = {}
                for profile, group in PAIRED.TLS_PROFILE_GROUPS.items():
                    factor = int(profile[1:]) + 1
                    records[profile] = {
                        "requested_group": group,
                        "wall_time_ns": 100.0 * factor,
                        "process_cpu_time_ns": 50.0 * factor,
                        "client_to_server_bytes": 10 + factor,
                        "server_to_client_bytes": 20 + factor,
                        "total_handshake_bytes": 30 + factor,
                        "success": True,
                    }
                blocks.append(
                    PAIRED.PairedBlock(run_id, f"replicate-{replicate:02d}", block, records)
                )
    return blocks


def _median_counterexample_blocks() -> list[object]:
    blocks = []
    run_ratios = {"baseline": 2.0, "confirmatory": 4.0}
    for run_id, ratio in run_ratios.items():
        for replicate in range(1, 4):
            records = {}
            for profile, group in PAIRED.TLS_PROFILE_GROUPS.items():
                value = 100.0
                if profile == "P1":
                    value = 100.0 * ratio
                if profile == "P3":
                    value = 100.0
                records[profile] = {
                    "run_id": run_id,
                    "replicate_id": f"replicate-{replicate:02d}",
                    "block": 0,
                    "requested_group": group,
                    "wall_time_ns": value,
                    "process_cpu_time_ns": value,
                    "client_to_server_bytes": int(value),
                    "server_to_client_bytes": int(value),
                    "total_handshake_bytes": int(value),
                    "success": True,
                }
            blocks.append(PAIRED.PairedBlock(run_id, f"replicate-{replicate:02d}", 0, records))
    return blocks


def test_complete_block_pairing_independent_of_execution_order(tmp_path: Path) -> None:
    blocks = PAIRED.pair_tls_blocks("fixture-run", _raw_tls_fixture(tmp_path), _config())

    assert len(blocks) == 600
    assert set(blocks[0].records_by_profile) == set(PAIRED.TLS_PROFILE_GROUPS)
    assert blocks[0].records_by_profile["P0"]["requested_group"] == "X25519"


@pytest.mark.parametrize("mutate", ["missing", "duplicate", "failed"])
def test_pairing_rejects_missing_duplicate_and_failed_records(
    tmp_path: Path, mutate: str
) -> None:
    with pytest.raises(ValueError):
        PAIRED.pair_tls_blocks("fixture-run", _raw_tls_fixture(tmp_path, mutate=mutate), _config())


def test_exact_p0_ratios_within_block_ratios_and_logs() -> None:
    rows = PAIRED.relative_tls_rows(_toy_blocks())
    p0_rows = [row for row in rows if row["profile_id"] == "P0"]
    p1 = next(row for row in rows if row["profile_id"] == "P1")

    for row in p0_rows:
        assert all(value == 1.0 for value in row["ratios_to_reference"].values())
        assert all(value == 0.0 for value in row["absolute_differences_from_reference"].values())
    assert p1["ratios_to_reference"]["wall_time_ratio"] == 2.0
    assert p1["absolute_differences_from_reference"]["wall_time_ns"] == 100.0
    assert p1["log_timing_ratios_to_reference"]["log_wall_time_ratio"] == pytest.approx(
        0.6931471805599453
    )


def test_all_pair_reciprocal_consistency() -> None:
    diagnostics = PAIRED.tls_reciprocity_diagnostics(_toy_blocks())
    matrix = PAIRED.pairwise_tls_matrix(_toy_blocks(), bootstrap_iterations=20)

    assert matrix["P1"]["P0"]["wall_time_ns"]["median_ratio"] == 2.0
    assert matrix["P0"]["P1"]["wall_time_ns"]["median_ratio"] == 0.5
    assert diagnostics["validation_passed"] is True
    assert diagnostics["failing_block_count"] == 0
    assert diagnostics["maximum_absolute_product_error"] <= PAIRED.RECIPROCAL_ABS_TOLERANCE


def test_floating_point_reciprocal_ratios_pass_within_tolerance() -> None:
    records = {}
    for profile, group in PAIRED.TLS_PROFILE_GROUPS.items():
        value = 0.1 + (0.2 if profile == "P1" else 0.7)
        records[profile] = {
            "requested_group": group,
            "wall_time_ns": value,
            "process_cpu_time_ns": value,
            "client_to_server_bytes": value,
            "server_to_client_bytes": value,
            "total_handshake_bytes": value,
            "success": True,
        }
    block = PAIRED.PairedBlock("run", "replicate-01", 1, records)

    diagnostics = PAIRED.tls_reciprocity_diagnostics([block])

    assert diagnostics["validation_passed"] is True


def test_reciprocal_mismatch_outside_tolerance_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def bad_ratio(*_args: object, **_kwargs: object) -> float:
        return 2.0

    monkeypatch.setattr(PAIRED, "metric_ratio", bad_ratio)

    with pytest.raises(ValueError, match="reciprocal product failed"):
        PAIRED.tls_reciprocity_diagnostics(_toy_blocks()[:1])


def test_wrong_block_identity_is_rejected() -> None:
    blocks = _toy_blocks()
    bad_records = dict(blocks[0].records_by_profile)
    bad_p1 = dict(bad_records["P1"])
    bad_p1["block"] = 999
    bad_records["P1"] = bad_p1
    bad = PAIRED.PairedBlock("baseline", "replicate-01", 0, bad_records)

    with pytest.raises(ValueError, match="mismatched block"):
        PAIRED.tls_reciprocity_diagnostics([bad])


def test_missing_profile_in_direct_block_is_rejected() -> None:
    blocks = _toy_blocks()
    records = dict(blocks[0].records_by_profile)
    records.pop("P3")
    bad = PAIRED.PairedBlock("baseline", "replicate-01", 0, records)

    with pytest.raises(ValueError, match="expected profiles"):
        PAIRED.tls_reciprocity_diagnostics([bad])


@pytest.mark.parametrize("bad_value", [0.0, -1.0, math.nan, math.inf, -math.inf])
def test_ratio_validation_rejects_zero_negative_nan_and_infinity(bad_value: float) -> None:
    with pytest.raises(ValueError):
        PAIRED.finite_positive_ratio(bad_value, 1.0, label="fixture")
    with pytest.raises(ValueError):
        PAIRED.finite_positive_ratio(1.0, bad_value, label="fixture")


def test_p1_p3_wall_time_fixture_validates_at_block_level() -> None:
    blocks = _median_counterexample_blocks()

    diagnostics = PAIRED.tls_reciprocity_diagnostics(blocks)

    assert diagnostics["validation_passed"] is True
    assert diagnostics["failing_block_count"] == 0


def test_even_sample_aggregate_medians_need_not_be_reciprocal() -> None:
    blocks = _median_counterexample_blocks()

    diagnostics = PAIRED.tls_reciprocity_diagnostics(blocks)
    matrix = PAIRED.pairwise_tls_matrix(blocks, bootstrap_iterations=20)

    assert diagnostics["validation_passed"] is True
    forward = matrix["P1"]["P3"]["wall_time_ns"]["directional_hierarchical_estimate"]
    reverse = matrix["P3"]["P1"]["wall_time_ns"]["directional_hierarchical_estimate"]
    assert forward == 3.0
    assert reverse == 0.375
    assert forward * reverse != 1.0
    assert matrix["P1"]["P3"]["wall_time_ns"]["symmetric_display_estimate"] == 3.0
    assert matrix["P3"]["P1"]["wall_time_ns"]["symmetric_display_estimate"] == pytest.approx(
        1.0 / 3.0
    )


def test_aggregated_pairwise_medians_are_not_reciprocal_validated() -> None:
    matrix = PAIRED.pairwise_tls_matrix(_median_counterexample_blocks(), bootstrap_iterations=20)

    assert matrix["P1"]["P3"]["wall_time_ns"]["directional_hierarchical_estimate"] == 3.0


def test_hierarchical_replicate_run_aggregation_and_cross_run_difference() -> None:
    rows = PAIRED.relative_tls_rows(_toy_blocks())
    summary = PAIRED.hierarchical_tls_summary(rows, "baseline", "confirmatory")

    p2 = summary["wall_time_ns"]["P2"]
    assert len(p2["replicate_medians"]) == 6
    assert p2["baseline_run_median"] == 3.0
    assert p2["confirmatory_run_median"] == 3.0
    assert p2["final_relative_estimate"] == 3.0
    assert p2["baseline_confirmatory_relative_difference"] == 0.0


def test_paired_hierarchical_bootstrap_is_reproducible_and_preserves_pairing() -> None:
    first = PAIRED.hierarchical_paired_bootstrap_ci(
        _toy_blocks(), "P1", "wall_time_ns", iterations=200, seed=123
    )
    second = PAIRED.hierarchical_paired_bootstrap_ci(
        _toy_blocks(), "P1", "wall_time_ns", iterations=200, seed=123
    )

    assert first == second
    assert first["lower"] == 2.0
    assert first["upper"] == 2.0


def test_relative_stability_gate_threshold_and_absolute_instability_visibility() -> None:
    rows = PAIRED.relative_tls_rows(_toy_blocks())
    summary = PAIRED.hierarchical_tls_summary(rows, "baseline", "confirmatory")
    bootstrap = {
        profile: {
            metric: {"lower": 1.0, "upper": 1.0}
            for metric in PAIRED.TLS_METRICS
        }
        for profile in PAIRED.TLS_PROFILE_GROUPS
    }
    gate = PAIRED.relative_quality_gate(
        summary,
        bootstrap,
        absolute_timing_stability={"absolute_timing_stability_passed": False},
        compatibility_passed=True,
        complete_block_count=1200,
        expected_block_count=1200,
    )

    assert gate["absolute_timing_stability_passed"] is False
    assert gate["paired_relative_timing_stability_passed"] is True
    assert gate["relative_cost_usable_for_selector"] is True


def test_relative_gate_rejects_scientific_incompatibility() -> None:
    rows = PAIRED.relative_tls_rows(_toy_blocks())
    summary = PAIRED.hierarchical_tls_summary(rows, "baseline", "confirmatory")
    bootstrap = {
        profile: {
            metric: {"lower": 1.0, "upper": 1.0}
            for metric in PAIRED.TLS_METRICS
        }
        for profile in PAIRED.TLS_PROFILE_GROUPS
    }

    gate = PAIRED.relative_quality_gate(
        summary,
        bootstrap,
        absolute_timing_stability={"absolute_timing_stability_passed": True},
        compatibility_passed=False,
        complete_block_count=1200,
        expected_block_count=1200,
    )

    assert gate["paired_relative_timing_stability_passed"] is False


def test_catalog_profile_mapping_validation_rejects_mismatch() -> None:
    with pytest.raises(ValueError):
        PAIRED.validate_catalog_profile_mapping(REPO_ROOT, {"P0": "not-X25519"})


def test_output_replacement_safety(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "existing.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError), PAIRED.staged_report_dir(
        output, replace_existing=False
    ):
        pass


def test_failed_staged_output_does_not_leave_completed_directory(tmp_path: Path) -> None:
    output = tmp_path / "report"

    with pytest.raises(RuntimeError), PAIRED.staged_report_dir(
        output, replace_existing=False
    ) as staging:
        (staging / "partial.json").write_text("{}", encoding="utf-8")
        raise RuntimeError("fixture failure")

    assert not output.exists()


def test_replace_existing_is_atomic(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "old.json").write_text("old", encoding="utf-8")

    with PAIRED.staged_report_dir(output, replace_existing=True) as staging:
        (staging / "new.json").write_text("new", encoding="utf-8")

    assert not (output / "old.json").exists()
    assert (output / "new.json").read_text(encoding="utf-8") == "new"


def test_pairing_does_not_modify_raw_directory_bytes(tmp_path: Path) -> None:
    run_dir = _raw_tls_fixture(tmp_path)
    before = {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file()
    }

    PAIRED.pair_tls_blocks("fixture-run", run_dir, _config())

    after = {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file()
    }
    assert after == before
