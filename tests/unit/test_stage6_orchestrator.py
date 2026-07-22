"""Stage 6 bundle orchestration tests."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.models.stage6_reports import (
    FeasibleRegressionValidationReport,
    SafeAbortValidationReport,
)

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

conflict_stage = importlib.import_module("validate_conflict_certificate_stage")
safe_abort_stage = importlib.import_module("validate_safe_abort_stage")
validate_stage6 = importlib.import_module("validate_stage6")

SCENARIOS = {
    "TLS-group-capability-conflict",
    "assurance-floor-conflict",
    "lease-policy-conflict",
    "multi-cause-conflict",
    "no-common-profile",
}
ABORT_SCENARIOS = {
    "TLS-group-capability-conflict",
    "assurance-floor-conflict",
    "lease-policy-conflict",
    "multi-cause-conflict",
    "no-common-profile",
}
SCIENTIFIC_JSON = {
    "conflict_stage_validation.json",
    "safe_abort_validation.json",
    "feasible_regression_validation.json",
    "adversarial_conflict_validation.json",
    "stage6_bundle_validation.json",
}


def test_component_default_output_directories_do_not_collide(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["validate_conflict_certificate_stage.py"])
    conflict_stage.main()
    monkeypatch.setattr(sys, "argv", ["validate_safe_abort_stage.py"])
    safe_abort_stage.main()

    assert Path("artifacts/conflicts-component/conflict-certificates").is_dir()
    assert Path("artifacts/conflicts-component/safe-aborts").is_dir()
    assert not Path("artifacts/conflicts").exists()


def test_one_component_cannot_erase_another_component(tmp_path: Path) -> None:
    conflict_dir = tmp_path / "artifacts/conflicts-component/conflict-certificates"
    abort_dir = tmp_path / "artifacts/conflicts-component/safe-aborts"
    abort_dir.mkdir(parents=True)
    sentinel = abort_dir / "sentinel.txt"
    sentinel.write_text("owned by safe abort\n", encoding="utf-8")

    with staged_report_dir(conflict_dir, replace_existing=True) as out:
        conflict_stage._write_conflict_artifacts(out)

    assert sentinel.read_text(encoding="utf-8") == "owned by safe abort\n"


def test_failed_bundle_generation_preserves_existing_artifact_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "artifacts/conflicts"
    output.mkdir(parents=True)
    existing = output / "existing.json"
    existing.write_text('{"old":true}\n', encoding="utf-8")

    def fail_abort_artifacts(out: Path, *, write_checksums: bool = True) -> None:
        raise RuntimeError("forced safe-abort failure")

    monkeypatch.setattr(validate_stage6, "_write_abort_artifacts", fail_abort_artifacts)
    with pytest.raises(RuntimeError, match="forced safe-abort failure"):
        validate_stage6.validate_stage6(output, replace_existing=True)

    assert existing.read_text(encoding="utf-8") == '{"old":true}\n'
    assert list(output.iterdir()) == [existing]


def test_successful_replacement_is_complete_and_removes_stale_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    stale = output / "certificates/stale.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"stale":true}\n', encoding="utf-8")

    report = validate_stage6.validate_stage6(output, replace_existing=True)

    assert report["validation_passed"] is True
    assert not stale.exists()
    assert (output / "checksums.sha256").is_file()
    assert not any(".components" in path.parts for path in output.rglob("*"))


def test_complete_expected_artifact_inventory(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)

    top_level = {path.name for path in output.iterdir()}
    assert top_level == {
        "conflict_stage_validation.json",
        "safe_abort_validation.json",
        "feasible_regression_validation.json",
        "adversarial_conflict_validation.json",
        "stage6_bundle_validation.json",
        "certificates",
        "failure_transcripts",
        "abort_records",
        "remediation_reports",
        "checksums.sha256",
    }
    assert {path.stem for path in (output / "certificates").glob("*.json")} == SCENARIOS
    assert {path.stem for path in (output / "remediation_reports").glob("*.json")} == SCENARIOS
    failure_transcripts = {path.stem for path in (output / "failure_transcripts").glob("*.json")}
    assert failure_transcripts == ABORT_SCENARIOS
    assert {path.stem for path in (output / "abort_records").glob("*.json")} == ABORT_SCENARIOS

    bundle = json.loads((output / "stage6_bundle_validation.json").read_text(encoding="utf-8"))
    assert bundle["expected_infeasible_scenario_count"] == 5
    assert bundle["generated_certificate_count"] == 5
    assert bundle["generated_failure_transcript_count"] == 5
    assert bundle["generated_abort_record_count"] == 5
    assert bundle["generated_remediation_report_count"] == 5
    assert bundle["safe_abort_scenario_count"] == 5
    assert bundle["feasible_regression_scenario_count"] == 4
    assert bundle["adversarial_case_count"] == 15
    assert bundle["validation_passed"] is True
    assert set(bundle["report_content_hashes"]) == {
        "conflict_stage_validation.json",
        "safe_abort_validation.json",
        "feasible_regression_validation.json",
        "adversarial_conflict_validation.json",
    }


def test_all_generated_files_appear_in_checksums(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)

    checksum_names = {
        line.split("  ", 1)[1]
        for line in (output / "checksums.sha256").read_text(encoding="utf-8").splitlines()
    }
    artifact_names = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    assert checksum_names == artifact_names
    validate_stage6.verify_checksums(output)


def test_deterministic_rerun_produces_byte_identical_scientific_json(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    validate_stage6.validate_stage6(first, replace_existing=False)
    validate_stage6.validate_stage6(second, replace_existing=False)

    for relative_name in SCIENTIFIC_JSON:
        assert (first / relative_name).read_bytes() == (second / relative_name).read_bytes()
    for directory in (
        "certificates",
        "failure_transcripts",
        "abort_records",
        "remediation_reports",
    ):
        for path in sorted((first / directory).glob("*.json")):
            assert path.read_bytes() == (second / directory / path.name).read_bytes()


def test_stage5_protocol_artifacts_remain_byte_identical(tmp_path: Path) -> None:
    stage5_files = sorted(Path("artifacts/protocol").rglob("*.json"))
    before = {path: path.read_bytes() for path in stage5_files}

    validate_stage6.validate_stage6(tmp_path / "artifacts/conflicts", replace_existing=False)

    after = {path: path.read_bytes() for path in stage5_files}
    assert after == before


def test_feasible_regression_contains_only_four_feasible_scenarios(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    feasible = json.loads((output / "feasible_regression_validation.json").read_text())

    assert feasible["scenario_count"] == 4
    assert {item["scenario_id"] for item in feasible["scenarios"]} == {
        "low-risk-public-tool",
        "sensitive-enterprise-api",
        "critical-edge-command",
        "low-risk-quantum-ready-tool",
    }
    assert "abort_hash" not in json.dumps(feasible)
    assert all(item["selection_unchanged"] for item in feasible["scenarios"])
    assert all(item["contract_hash_unchanged"] for item in feasible["scenarios"])
    assert all(item["feasibility_remains_true"] for item in feasible["scenarios"])


def test_complete_artifact_chains_include_no_common_and_assurance_abort(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)

    for scenario_id in SCENARIOS:
        assert (output / "certificates" / f"{scenario_id}.json").is_file()
        assert (output / "failure_transcripts" / f"{scenario_id}.json").is_file()
        assert (output / "abort_records" / f"{scenario_id}.json").is_file()
        assert (output / "remediation_reports" / f"{scenario_id}.json").is_file()


def test_assurance_and_lease_scenarios_are_isolated(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    conflict = json.loads((output / "conflict_stage_validation.json").read_text())
    by_id = {item["scenario_id"]: item for item in conflict["scenarios"]}

    assurance = by_id["assurance-floor-conflict"]
    assert assurance["category"] == "ASSURANCE_FLOOR_CONFLICT"
    assert assurance["diagnostics"]["capability_intersection_before_policy"]
    assert assurance["diagnostics"]["candidate_set_after_assurance_floor"] == ["P3", "P4"]
    assert assurance["diagnostics"]["final_common_safe_set"] == []
    assert assurance["diagnostics"]["ius_categories"] == ["minimum_assurance"]

    lease = by_id["lease-policy-conflict"]
    assert lease["category"] == "LEASE_CONFLICT"
    assert lease["diagnostics"]["task_minimum_lease_seconds"] == 900
    assert lease["diagnostics"]["agent_profile_maximum_lease_seconds"] == 300
    assert lease["diagnostics"]["otherwise_compatible_candidate_profiles"] == [
        "P0",
        "P1",
        "P2",
        "P3",
        "P4",
    ]
    assert lease["diagnostics"]["ius_categories"] == ["lease_limit"]


def test_adversarial_report_contains_fifteen_rejected_mutations(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    adversarial = json.loads((output / "adversarial_conflict_validation.json").read_text())

    assert adversarial["case_count"] == 15
    assert len(adversarial["attacks"]) == 15
    assert all(item["rejected"] for item in adversarial["attacks"])
    assert all(item["fail_closed"] for item in adversarial["attacks"])
    assert all(item["validation_passed"] for item in adversarial["attacks"])
    assert "abort_hash" not in json.dumps(adversarial)


def test_report_models_cannot_be_substituted_for_one_another(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    safe_payload = json.loads((output / "safe_abort_validation.json").read_text())

    SafeAbortValidationReport.model_validate(safe_payload)
    with pytest.raises(ValidationError):
        FeasibleRegressionValidationReport.model_validate(safe_payload)


def test_duplicated_report_payloads_cause_bundle_validation_failure(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    safe_payload = json.loads((output / "safe_abort_validation.json").read_text())
    safe_payload["artifact"] = "feasible_regression_validation"
    (output / "feasible_regression_validation.json").write_text(
        json.dumps(safe_payload, sort_keys=True), encoding="utf-8"
    )

    bundle = validate_stage6._bundle_report(output, checksum_validation_passed=True)
    assert bundle.validation_passed is False
    assert bundle.checksum_validation_passed is True


def test_incorrect_counts_cause_bundle_validation_failure(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    (output / "abort_records/no-common-profile.json").unlink()

    bundle = validate_stage6._bundle_report(output, checksum_validation_passed=True)
    assert bundle.validation_passed is False
    assert "abort-record-count" in bundle.validation_errors


def test_missing_cross_artifact_reference_causes_failure(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    abort_path = output / "abort_records/no-common-profile.json"
    abort = json.loads(abort_path.read_text())
    abort["failure_transcript_hash"] = "0" * 64
    abort_path.write_text(json.dumps(abort, sort_keys=True), encoding="utf-8")

    bundle = validate_stage6._bundle_report(output, checksum_validation_passed=True)
    assert bundle.validation_passed is False
    assert "no-common-profile:cross-artifact-reference" in bundle.validation_errors


def test_checksum_success_alone_cannot_make_semantic_validation_pass(tmp_path: Path) -> None:
    output = tmp_path / "artifacts/conflicts"
    validate_stage6.validate_stage6(output, replace_existing=False)
    (output / "failure_transcripts/assurance-floor-conflict.json").unlink()
    validate_stage6.write_checksums(output)
    validate_stage6.verify_checksums(output)

    bundle = validate_stage6._bundle_report(output, checksum_validation_passed=True)
    assert bundle.checksum_validation_passed is True
    assert bundle.validation_passed is False
