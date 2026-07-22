"""Unit tests for Stage 4A selector mechanics."""

from __future__ import annotations

import copy
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.evidence.decimal_json import load_decimal_json
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.preference import AgentCostPreference
from pqtrust_agent.models.selection import SelectionMode, classify_selection_mode
from pqtrust_agent.negotiation.cost_evidence import (
    CostEvidenceError,
    load_selector_cost_evidence,
)
from pqtrust_agent.negotiation.normalization import compute_global_anchors, normalize_vector
from pqtrust_agent.negotiation.pareto import pareto_filter
from pqtrust_agent.negotiation.regret import (
    compute_regret_rows,
    minimax_regret_select,
    weighted_cost,
)
from pqtrust_agent.negotiation.sensitivity import weight_grid
from pqtrust_agent.negotiation.validation import validate_selector_stage
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fixture_payload(catalog_hash: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    groups = {
        "P0": "X25519",
        "P1": "X25519MLKEM768",
        "P2": "SecP256r1MLKEM768",
        "P3": "MLKEM768",
        "P4": "SecP384r1MLKEM1024",
    }
    values = {
        "P0": (1.0, 1.0, 1.0),
        "P1": (1.2, 1.1, 2.0),
        "P2": (1.1, 1.4, 1.8),
        "P3": (1.5, 1.3, 2.2),
        "P4": (1.7, 1.6, 2.6),
    }
    source_raw_checksums = {
        "calibration-20260713-confirmatory": "b" * 64,
        "calibration-20260713-r2": "a" * 64,
    }
    scientific_hash = "c" * 64
    profiles = []
    for profile_id, (wall, cpu, bytes_) in values.items():
        profiles.append(
            {
                "profile_id": profile_id,
                "tls_group": groups[profile_id],
                "catalog_hash": catalog_hash,
                "scientific_design_hash": scientific_hash,
                "source_run_ids": [
                    "calibration-20260713-r2",
                    "calibration-20260713-confirmatory",
                ],
                "source_raw_checksums": source_raw_checksums,
                "wall_time_relative_estimate": wall,
                "cpu_time_relative_estimate": cpu,
                "total_handshake_byte_relative_estimate": bytes_,
                "wall_time_paired_bootstrap_interval": {
                    "lower": wall - 0.01,
                    "upper": wall + 0.01,
                    "confidence_level": 0.95,
                    "iterations": 100,
                    "seed": 7,
                },
                "cpu_time_paired_bootstrap_interval": {
                    "lower": cpu - 0.01,
                    "upper": cpu + 0.01,
                    "confidence_level": 0.95,
                    "iterations": 100,
                    "seed": 7,
                },
                "usability_status": {
                    "profile_id": profile_id,
                    "tls_group": groups[profile_id],
                    "paired_relative_timing_stability_passed": True,
                    "timing_metrics": {"wall_time_ns": True, "process_cpu_time_ns": True},
                },
            }
        )
    selector = {
        "artifact_type": "calibrated_tls_selector_cost_evidence",
        "policy_specific_cost_vector": False,
        "profiles": profiles,
    }
    gate = {
        "schema_version": 1,
        "absolute_timing_stability_passed": False,
        "paired_relative_timing_stability_passed": True,
        "relative_cost_usable_for_selector": True,
        "complete_paired_blocks": 1200,
        "profile_gates": {
            profile_id: {
                "profile_id": profile_id,
                "tls_group": group,
                "paired_relative_timing_stability_passed": True,
                "timing_metrics": {"wall_time_ns": True, "process_cpu_time_ns": True},
            }
            for profile_id, group in groups.items()
        },
    }
    manifest = {
        "compatibility": {
            "comparison_compatible": True,
            "catalog_hashes_match": True,
            "scientific_design_hashes_match": True,
            "baseline_scientific_design_hash": scientific_hash,
            "confirmatory_scientific_design_hash": scientific_hash,
            "details": {
                "catalog_hash": {"baseline": catalog_hash, "confirmatory": catalog_hash}
            },
        },
        "integrity": {
            "baseline": {
                "validation_passed": True,
                "raw_run": "calibration-20260713-r2",
                "raw_run_checksum": "a" * 64,
                "checks": {"raw_checksums_valid": True},
            },
            "confirmatory": {
                "validation_passed": True,
                "raw_run": "calibration-20260713-confirmatory",
                "raw_run_checksum": "b" * 64,
                "checks": {"raw_checksums_valid": True},
            },
        },
        "source_raw_checksums": source_raw_checksums,
    }
    return selector, gate, manifest


def _write_evidence_dir(tmp_path: Path, catalog_hash: str) -> Path:
    selector, gate, manifest = _fixture_payload(catalog_hash)
    for name, payload in {
        "selector_tls_cost_evidence.json": selector,
        "relative_cost_quality_gate.json": gate,
        "analysis_manifest.json": manifest,
    }.items():
        _write_json(tmp_path / name, payload)
    lines = [
        f"{_sha256(tmp_path / name)}  {name}"
        for name in (
            "selector_tls_cost_evidence.json",
            "relative_cost_quality_gate.json",
            "analysis_manifest.json",
        )
    ]
    (tmp_path / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def catalog() -> Any:
    return load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))


@pytest.fixture()
def fixture_evidence_dir(tmp_path: Path, catalog: Any) -> Path:
    return _write_evidence_dir(tmp_path, catalog.catalog_hash())


@pytest.fixture(scope="session")
def stage4b_reports() -> dict[str, Any]:
    return validate_selector_stage(
        catalog_path=Path("configs/profiles/trust_profiles.yaml"),
        agents_dir=Path("configs/agents"),
        policies_dir=Path("configs/policies"),
        preferences_dir=Path("configs/preferences"),
        scenarios_dir=Path("configs/scenarios"),
        cost_evidence_dir=Path("artifacts/paired-cost-calibration/r2-vs-confirmatory"),
    )


def _balanced(agent_id: str = "a") -> AgentCostPreference:
    return AgentCostPreference(
        preference_id=f"{agent_id}-pref",
        preference_version=1,
        agent_id=agent_id,
        wall_time_weight_bps=4000,
        process_cpu_time_weight_bps=3000,
        total_handshake_bytes_weight_bps=3000,
        description="test preference",
    )


def test_cost_evidence_loader_verifies_checksums_and_decimal(
    fixture_evidence_dir: Path,
    catalog: Any,
) -> None:
    evidence = load_selector_cost_evidence(fixture_evidence_dir, catalog)
    assert evidence.relative_cost_usable_for_selector is True
    assert evidence.paired_relative_timing_stability_passed is True
    assert evidence.absolute_timing_stability_passed is False
    assert evidence.complete_paired_blocks == 1200
    assert evidence.by_profile()["P1"].wall_time == Decimal("1.2")
    parsed = load_decimal_json(fixture_evidence_dir / "selector_tls_cost_evidence.json")
    assert isinstance(parsed["profiles"][1]["wall_time_relative_estimate"], Decimal)


def test_cost_evidence_rejects_unusable_gate(fixture_evidence_dir: Path, catalog: Any) -> None:
    gate = json.loads((fixture_evidence_dir / "relative_cost_quality_gate.json").read_text())
    gate["relative_cost_usable_for_selector"] = False
    _write_json(fixture_evidence_dir / "relative_cost_quality_gate.json", gate)
    with pytest.raises(CostEvidenceError, match="checksum mismatch"):
        load_selector_cost_evidence(fixture_evidence_dir, catalog)


def test_cost_evidence_rejects_catalog_and_tls_mismatch(
    tmp_path: Path,
    catalog: Any,
) -> None:
    selector, gate, manifest = _fixture_payload(catalog.catalog_hash())
    selector["profiles"][0]["catalog_hash"] = "d" * 64
    for name, payload in {
        "selector_tls_cost_evidence.json": selector,
        "relative_cost_quality_gate.json": gate,
        "analysis_manifest.json": manifest,
    }.items():
        _write_json(tmp_path / name, payload)
    (tmp_path / "checksums.sha256").write_text(
        "\n".join(
            f"{_sha256(tmp_path / name)}  {name}"
            for name in (
                "selector_tls_cost_evidence.json",
                "relative_cost_quality_gate.json",
                "analysis_manifest.json",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(CostEvidenceError, match="catalog hash mismatch"):
        load_selector_cost_evidence(tmp_path, catalog)


def test_cost_evidence_rejects_nan_infinity_negative_and_duplicate_profile(
    tmp_path: Path,
    catalog: Any,
) -> None:
    selector, gate, manifest = _fixture_payload(catalog.catalog_hash())
    selector["profiles"][1]["wall_time_relative_estimate"] = -1
    selector["profiles"][2] = copy.deepcopy(selector["profiles"][1])
    selector["profiles"][2]["profile_id"] = "P1"
    for name, payload in {
        "selector_tls_cost_evidence.json": selector,
        "relative_cost_quality_gate.json": gate,
        "analysis_manifest.json": manifest,
    }.items():
        _write_json(tmp_path / name, payload)
    (tmp_path / "checksums.sha256").write_text(
        "\n".join(
            f"{_sha256(tmp_path / name)}  {name}"
            for name in (
                "selector_tls_cost_evidence.json",
                "relative_cost_quality_gate.json",
                "analysis_manifest.json",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(CostEvidenceError):
        load_selector_cost_evidence(tmp_path, catalog)
    (tmp_path / "bad.json").write_text('{"x": NaN}', encoding="utf-8")
    with pytest.raises(Exception, match="non-finite"):
        load_decimal_json(tmp_path / "bad.json")


def test_global_normalization_and_weighted_components(
    fixture_evidence_dir: Path,
    catalog: Any,
) -> None:
    evidence = load_selector_cost_evidence(fixture_evidence_dir, catalog)
    anchors = compute_global_anchors(evidence.profiles)
    p1 = normalize_vector(evidence.by_profile()["P1"].measured_vector(), anchors)
    assert all(Decimal(0) <= value <= Decimal(1) for value in p1.values())
    cost = weighted_cost(p1, _balanced())
    assert cost.total == sum(cost.components.values(), Decimal(0))
    assert _balanced().preference_hash() == _balanced().preference_hash()
    with pytest.raises(ValueError, match="sum"):
        AgentCostPreference(
            preference_id="bad",
            preference_version=1,
            agent_id="bad",
            wall_time_weight_bps=1,
            process_cpu_time_weight_bps=1,
            total_handshake_bytes_weight_bps=1,
            description="bad",
        )


def test_pareto_dominance_multiple_dominators_and_frontier_collapse() -> None:
    vectors = {
        "P0": {
            "wall_time": Decimal("1"),
            "process_cpu_time": Decimal("1"),
            "total_handshake_bytes": Decimal("1"),
        },
        "P1": {
            "wall_time": Decimal("2"),
            "process_cpu_time": Decimal("2"),
            "total_handshake_bytes": Decimal("2"),
        },
        "P2": {
            "wall_time": Decimal("1"),
            "process_cpu_time": Decimal("2"),
            "total_handshake_bytes": Decimal("2"),
        },
    }
    frontier, removed = pareto_filter(("P0", "P1", "P2"), vectors)
    assert frontier == ("P0",)
    assert set(removed["P1"].dominating_profile_ids) == {"P0", "P2"}
    assert len(frontier) == 1


def test_regret_minimax_tie_break_and_profile_id_final_tie_break() -> None:
    normalized = {
        "P1": {
            "wall_time": Decimal("0.5"),
            "process_cpu_time": Decimal("0.1"),
            "total_handshake_bytes": Decimal("0.4"),
        },
        "P2": {
            "wall_time": Decimal("0.4"),
            "process_cpu_time": Decimal("0.2"),
            "total_handshake_bytes": Decimal("0.4"),
        },
    }
    rows = compute_regret_rows(("P1", "P2"), normalized, _balanced("i"), _balanced("r"))
    assert min(row.initiator_regret for row in rows) == 0
    assert min(row.responder_regret for row in rows) == 0
    selected, trace = minimax_regret_select(rows)
    assert selected in {"P1", "P2"}
    tied_normalized = {
        "P1": {
            "wall_time": Decimal("0.1"),
            "process_cpu_time": Decimal("0.1"),
            "total_handshake_bytes": Decimal("0.1"),
        },
        "P2": {
            "wall_time": Decimal("0.1"),
            "process_cpu_time": Decimal("0.1"),
            "total_handshake_bytes": Decimal("0.1"),
        },
    }
    tied = compute_regret_rows(("P1", "P2"), tied_normalized, _balanced("i"), _balanced("r"))
    assert minimax_regret_select(tied)[0] == "P1"
    assert "profile_id" in trace[0]


def test_weight_grid_is_deterministic() -> None:
    grid = weight_grid()
    assert grid[0] == (0, 0, 10000)
    assert grid[-1] == (10000, 0, 0)
    assert len(grid) == 66
    assert all(sum(item) == 10000 for item in grid)


def test_selection_mode_classification() -> None:
    assert (
        classify_selection_mode(common_safe_candidate_count=1, pareto_candidate_count=1)
        is SelectionMode.SINGLETON_COMMON_SAFE_SET
    )
    assert (
        classify_selection_mode(common_safe_candidate_count=3, pareto_candidate_count=1)
        is SelectionMode.PARETO_FRONTIER_COLLAPSE
    )
    assert (
        classify_selection_mode(common_safe_candidate_count=3, pareto_candidate_count=2)
        is SelectionMode.BILATERAL_MINIMAX_REGRET
    )


def test_quantum_ready_manifest_policy_and_measured_frontier(catalog: Any) -> None:
    scenario = load_scenario(Path("configs/scenarios/low_risk_quantum_ready_tool.yaml"))
    manifest = load_agent_manifest(Path("configs/agents/quantum_ready_tool_agent.yaml"))
    policy = load_agent_policy(Path("configs/policies/quantum_ready_tool_agent.yaml"))
    assert manifest.agent_id == "quantum-ready-tool-agent"
    assert manifest.supported_profile_ids == ("P0", "P1", "P3")
    assert policy.agent_id == manifest.agent_id
    assert policy.allowed_profile_ids == ("P0", "P1", "P3")
    assert policy.denied_profile_ids == ()
    assert policy.base_requirement.key_establishment_threats == frozenset({"classical"})
    compilation = compile_local_policy(
        catalog,
        manifest,
        policy,
        scenario.task,
        scenario.evaluation_time_utc,
    )
    assert compilation.safe_profile_ids == ("P0", "P1", "P3")
    evidence = load_selector_cost_evidence(
        Path("artifacts/paired-cost-calibration/r2-vs-confirmatory"),
        catalog,
    )
    raw = {profile.profile_id: profile.measured_vector() for profile in evidence.profiles}
    frontier, removed = pareto_filter(("P0", "P1", "P3"), raw)
    assert frontier == ("P0", "P3")
    assert removed["P1"].dominating_profile_ids == ("P0", "P3")


def test_stage4b_report_semantics_and_candidate_audit(
    stage4b_reports: dict[str, Any],
) -> None:
    main = stage4b_reports["selector_stage_validation.json"]
    by_id = {scenario["scenario_id"]: scenario for scenario in main["scenarios"]}
    assert by_id["critical-edge-command"]["selection_mode"] == "singleton_common_safe_set"
    assert by_id["low-risk-public-tool"]["selection_mode"] == "pareto_frontier_collapse"
    assert by_id["sensitive-enterprise-api"]["selection_mode"] == "pareto_frontier_collapse"
    assert (
        by_id["low-risk-public-tool"]["weight_sensitivity"]["classification"]
        == "pareto_frontier_collapse"
    )
    quantum = by_id["low-risk-quantum-ready-tool"]
    assert quantum["selection_mode"] == "bilateral_minimax_regret"
    assert quantum["minimax_regret_exercised"] is True
    assert quantum["common_safe_set"] == ["P0", "P1", "P3"]
    assert quantum["pareto_frontier"] == ["P0", "P3"]
    assert [item["profile_id"] for item in quantum["candidate_audit"]] == ["P0", "P1", "P3"]
    for scenario in main["scenarios"]:
        common = set(scenario["common_safe_set"])
        assert all(item["profile_id"] in common for item in scenario["candidate_audit"])
    p1 = {item["profile_id"]: item for item in quantum["candidate_audit"]}["P1"]
    assert p1["pareto_status"] == "dominated"
    assert p1["eligible_for_regret_computation"] is False
    assert p1["dominating_profile_ids"] == ["P0", "P3"]
    assert p1["regret_exclusion_reason"] == "removed_by_measured_pareto_dominance"
    assert (
        stage4b_reports["preference_conflict_evaluation.json"]["total_joint_preference_pairs"]
        == 4356
    )
    assert stage4b_reports["fairness_comparison.json"]["validation_passed"] is True
    conflict_count = stage4b_reports["fairness_comparison.json"]["conflict_pair_count"]
    assert all(
        method["fairness_gain"]["negative_gain_count"] == 0
        for name, method in stage4b_reports["fairness_comparison.json"]["methods"].items()
        if name != "bilateral_minimax_regret"
    )
    assert all(
        method["strict_minimax_improvement_count"]
        + method["tie_count"]
        + method["degradation_count"]
        == conflict_count
        for name, method in stage4b_reports["fairness_comparison.json"]["methods"].items()
        if name != "bilateral_minimax_regret"
    )
    assert (
        "registered_preference_result"
        in stage4b_reports["nondegenerate_frontier_evaluation.json"]
    )


def test_stage4b_deterministic_outputs_and_evidence_unchanged(
    stage4b_reports: dict[str, Any],
) -> None:
    first = stage4b_reports
    second = copy.deepcopy(stage4b_reports)
    for name in (
        "nondegenerate_frontier_evaluation.json",
        "preference_conflict_evaluation.json",
        "fairness_comparison.json",
    ):
        assert first[name] == second[name]
        assert json.dumps(first[name], sort_keys=True, default=str) == json.dumps(
            second[name],
            sort_keys=True,
            default=str,
        )
    assert (
        _sha256(
            Path(
                "artifacts/paired-cost-calibration/r2-vs-confirmatory/"
                "selector_tls_cost_evidence.json"
            )
        )
        == "637d7da747ddd937e50e780d1daf9779c16db593ac66a963e3ebf2f63e87a072"
    )
    assert (
        _sha256(
            Path(
                "artifacts/paired-cost-calibration/r2-vs-confirmatory/"
                "tls_relative_by_replicate.json"
            )
        )
        == "aa6293f436dd9c44ddf4bb2af02ed1b4be9e2c2c90dbe8cebc5ef9ebae0c4b5f"
    )
