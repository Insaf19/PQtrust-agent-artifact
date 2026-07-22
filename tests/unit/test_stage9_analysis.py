from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pqtrust_agent.analysis import stage9

REPO = Path(__file__).resolve().parents[2]
RUN_DIR = REPO / "runs/stage8/stage8-final-20260714-r2"


def test_stage9_raw_data_count_verification_and_stage8_bytes_unchanged() -> None:
    before = stage9.sha256_file(RUN_DIR / "raw" / "feasible_sessions.jsonl")
    result = stage9.verify_stage8_inputs(
        RUN_DIR, REPO / "artifacts/campaigns/final", stage9.load_plan(REPO / stage9.PLAN_PATH)
    )
    after = stage9.sha256_file(RUN_DIR / "raw" / "feasible_sessions.jsonl")
    assert result["validation_passed"] is True
    assert result["counts"] == {
        "feasible": 480,
        "infeasible": 150,
        "adversarial": 200,
        "concurrency": 100,
        "component": 110,
    }
    assert before == after


def test_pairing_logic_uses_scenario_block_repetition_units() -> None:
    rows = stage9.load_observations(RUN_DIR)["feasible"]
    paired = stage9.paired_differences(rows, "total_session_wall_time_ns", "canonical_first_safe")
    assert len(paired) == 120
    assert all(item["paired_comparison_id"].startswith("pair:") for item in paired)
    assert {item["scenario_id"] for item in paired} == {
        "critical-edge-command",
        "low-risk-public-tool",
        "low-risk-quantum-ready-tool",
        "sensitive-enterprise-api",
    }


def test_deterministic_bootstrap_effect_size_holm_and_zero_bounds() -> None:
    first = stage9.bootstrap_ci(
        [1.0, 2.0, 3.0], lambda values: sum(values) / len(values), repetitions=50, seed=7
    )
    second = stage9.bootstrap_ci(
        [1.0, 2.0, 3.0], lambda values: sum(values) / len(values), repetitions=50, seed=7
    )
    assert first == second
    corrected = stage9.holm_correction({"a": 0.01, "b": 0.04, "c": 0.03})
    assert corrected["a"] == pytest.approx(0.03)
    assert corrected["c"] == pytest.approx(0.06)
    assert 0 < stage9.exact_zero_violation_upper_bound(150) < 0.03
    row = stage9.paired_effect_row(
        [
            {
                "difference": 1.0,
                "baseline_value": 10.0,
                "metric": "m",
                "baseline_method": "b",
                "paired_comparison_id": "p1",
                "primary_observation_id": "o1",
                "baseline_observation_id": "o2",
            },
            {
                "difference": 2.0,
                "baseline_value": 10.0,
                "metric": "m",
                "baseline_method": "b",
                "paired_comparison_id": "p2",
                "primary_observation_id": "o3",
                "baseline_observation_id": "o4",
            },
        ]
    )
    assert row["paired_effect_size"] > 0


def test_no_pseudoreplication_and_required_inventory() -> None:
    plan = stage9.load_plan(REPO / stage9.PLAN_PATH)
    assert "scenario_id, block_id, repetition" in plan["paired_comparison_unit"]
    assert plan["figure_inventory"] == stage9.EXPECTED_FIGURES
    assert plan["table_inventory"] == list(stage9.EXPECTED_TABLES)
    assert plan["no_post_hoc_metric_substitution"] is True
    assert plan["no_exclusion_of_valid_slow_observations"] is True


def test_figure_data_provenance_and_determinism(tmp_path: Path) -> None:
    out = tmp_path / "analysis"
    stats = out / "statistics"
    stats.mkdir(parents=True)
    for name in (
        "analysis_validation.json",
        "fairness_analysis.json",
        "infeasible_analysis.json",
        "adversarial_analysis.json",
        "concurrency_analysis.json",
        "component_analysis.json",
    ):
        (stats / name).write_text("{}\n", encoding="utf-8")
    (stats / "descriptive_statistics.csv").write_text("a\n", encoding="utf-8")
    (stats / "paired_comparisons.csv").write_text("a\n", encoding="utf-8")
    stage9.generate_figure_data(out)
    first = stage9.sha256_file(out / "figure_data" / "figure-10" / "data.json")
    shutil.rmtree(out / "figure_data")
    stage9.generate_figure_data(out)
    second = stage9.sha256_file(out / "figure_data" / "figure-10" / "data.json")
    metadata = json.loads((out / "figure_data" / "figure-10" / "metadata.json").read_text())
    assert first == second
    assert metadata["source_raw_files"]
    assert (out / "figure_data" / "figure-10" / "caption.txt").exists()


def test_table_formatting_claim_restrictions_and_checksum_coverage(tmp_path: Path) -> None:
    fragment = stage9.latex_fragment(
        [{"metric_name": "a_b", "value": 1.23456}], ["metric_name", "value"]
    )
    assert r"a\_b" in fragment
    ledger = {
        "claims": [
            {
                "claim_id": "bad",
                "exact_proposed_claim_text": "The true violation probability is zero.",
                "allowed_wording": "observed zero violations",
            }
        ]
    }
    assert stage9.validate_claim_ledger(ledger)
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.txt").write_text("b\n", encoding="utf-8")
    stage9.write_checksums(tmp_path)
    checksum_text = (tmp_path / "checksums.sha256").read_text(encoding="utf-8")
    assert "a.txt" in checksum_text
    assert "nested/b.txt" in checksum_text
    assert stage9.verify_checksums(tmp_path) == []
