from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from pqtrust_agent.campaigns import stage8

REPO = Path(__file__).resolve().parents[2]
TEST_COMMIT = "7c4eaf33ffc8eb74f72af9887c78ae67283a8a1f"


@pytest.fixture()
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    cfg = stage8.load_yaml_config(REPO / "configs/campaigns/stage8_final_campaign.yaml")
    config_path = tmp_path / "stage8.yaml"
    config_path.write_text(yaml.safe_dump(cfg, sort_keys=True), encoding="utf-8")
    monkeypatch.setattr(stage8, "CONFIG_PATH", config_path)
    monkeypatch.setattr(stage8, "REGISTRATION_DIR", tmp_path / "registration")
    monkeypatch.setattr(stage8, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(stage8, "FINAL_DIR", tmp_path / "final")
    return cfg


def _write_registration(tmp_path: Path, cfg: dict[str, Any]) -> Path:
    registration = tmp_path / "registration"
    registration.mkdir()
    design = {
        "artifact": "stage8_registered_design",
        "campaign_design_hash": stage8.canonical_hash(cfg),
        "configuration": cfg,
        "registration_commit": TEST_COMMIT,
    }
    schedule = stage8.deterministic_schedule(cfg)
    preflight = {
        "artifact": "stage8_environment_preflight",
        "registration_commit": TEST_COMMIT,
        "validation_passed": True,
    }
    artifact_hash = stage8.registration_artifact_hash(design, preflight, schedule)
    design["registration_artifact_hash"] = artifact_hash
    preflight["registration_artifact_hash"] = artifact_hash
    stage8.write_json(registration / "registered_design.json", design)
    stage8.write_json(registration / "execution_schedule.json", schedule)
    stage8.write_json(registration / "environment_preflight.json", preflight)
    return registration


def test_campaign_configuration_canonicalization_is_stable(config: dict[str, Any]) -> None:
    first = stage8.canonical_hash(config)
    second = stage8.canonical_hash(json.loads(json.dumps(config)))
    assert first == second
    mutated = dict(config)
    mutated["deterministic_ordering_seed"] = 1
    assert stage8.canonical_hash(mutated) != first


def test_static_campaign_yaml_has_no_repository_commit(config: dict[str, Any]) -> None:
    assert "repository_commit" not in config


def test_registration_captures_clean_head_automatically(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {
            "artifact": "stage8_environment_preflight",
            "registration_commit": kwargs["registration_commit"],
            "validation_passed": True,
            "validation_errors": [],
        },
    )
    result = stage8.write_registration(tmp_path)
    assert result["registered_design"]["registration_commit"] == TEST_COMMIT
    assert result["environment_preflight"]["registration_commit"] == TEST_COMMIT
    assert result["registered_design"]["campaign_design_hash"] == stage8.canonical_hash(config)
    assert result["registered_design"]["registration_artifact_hash"]


def test_immutable_registration_and_dirty_repository_refusal(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    del config
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {
            "artifact": "stage8_environment_preflight",
            "registration_commit": kwargs["registration_commit"],
            "validation_passed": True,
            "validation_errors": [],
        },
    )
    first = stage8.write_registration(tmp_path)
    with pytest.raises(stage8.Stage8Error, match="already exists"):
        stage8.write_registration(tmp_path)
    assert stage8.load_json(stage8.REGISTRATION_DIR / "registered_design.json") == first[
        "registered_design"
    ]
    monkeypatch.setattr(stage8, "REGISTRATION_DIR", tmp_path / "registration-dirty")
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: True)
    with pytest.raises(stage8.Stage8Error, match="dirty Git"):
        stage8.write_registration(tmp_path)


def test_replacement_forbidden_after_measured_run_starts(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    del config
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {
            "artifact": "stage8_environment_preflight",
            "registration_commit": kwargs["registration_commit"],
            "validation_passed": True,
            "validation_errors": [],
        },
    )
    stage8.write_registration(tmp_path)
    raw = stage8.RUNS_DIR / "started" / "raw"
    raw.mkdir(parents=True)
    (raw / stage8.FEASIBLE_JSONL).write_text('{"observation_id":"obs-1"}\n', encoding="utf-8")
    with pytest.raises(stage8.Stage8Error, match="measured run has started"):
        stage8.write_registration(tmp_path, replace_existing=True)


def test_registration_is_deterministic_under_identical_design_and_head(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    del config
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {
            "artifact": "stage8_environment_preflight",
            "registration_commit": kwargs["registration_commit"],
            "platform": "test-platform",
            "python": "3.test",
            "validation_passed": True,
            "validation_errors": [],
        },
    )
    first = stage8.write_registration(tmp_path)
    second = stage8.write_registration(tmp_path, replace_existing=True)
    assert second["registered_design"] == first["registered_design"]
    assert second["environment_preflight"] == first["environment_preflight"]
    assert second["schedule"] == first["schedule"]


def test_schedule_determinism_and_paired_block_balance(config: dict[str, Any]) -> None:
    first = stage8.deterministic_schedule(config)
    second = stage8.deterministic_schedule(config)
    assert first["schedule_hash"] == second["schedule_hash"]
    assert first["observation_count"] == sum(stage8.EXPECTED.values())
    feasible = [item for item in first["observations"] if item["kind"] == "feasible"]
    assert len(feasible) == 480
    pairs = {(item["scenario_id"], item["block_id"], item["repetition"]) for item in feasible}
    assert all(
        len(
            [
                item
                for item in feasible
                if (item["scenario_id"], item["block_id"], item["repetition"]) == pair
            ]
        )
        == 4
        for pair in pairs
    )


def test_duplicate_observation_rejection_and_no_rewrite(
    tmp_path: Path, config: dict[str, Any]
) -> None:
    del config
    run_dir = tmp_path / "run"
    row = {"observation_id": "obs-1", "kind": "feasible"}
    stage8.append_observation(run_dir, "feasible", row)
    before = (run_dir / "raw" / stage8.FEASIBLE_JSONL).read_text(encoding="utf-8")
    with pytest.raises(stage8.Stage8Error, match="rewrite"):
        stage8.append_observation(run_dir, "feasible", row)
    after = (run_dir / "raw" / stage8.FEASIBLE_JSONL).read_text(encoding="utf-8")
    assert after == before


def test_interrupted_run_recovery_exact_inventory_and_incomplete_not_complete(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_registration(tmp_path, config)
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {"validation_passed": True, "validation_errors": []},
    )
    run_dir = stage8.prepare_run_dir(tmp_path, "resume-case")
    _, schedule = stage8.load_registration()
    first = schedule["observations"][0]
    row = stage8.synthetic_observation_for_tests(tmp_path, run_dir, first)
    stage8.append_observation(run_dir, first["kind"], row)
    assert not (run_dir / "RUN_COMPLETE").exists()
    assert stage8.count_raw(run_dir)["feasible"] == 1
    result = stage8.validate_run(run_dir, write_report=False)
    assert result["validation_passed"] is False
    assert any("missing observations" in err for err in result["validation_errors"])


def test_safety_and_adversarial_invariants_are_enforced(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_registration(tmp_path, config)
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {"validation_passed": True, "validation_errors": []},
    )
    run_dir = stage8.prepare_run_dir(tmp_path, "bad-invariants")
    _, schedule = stage8.load_registration()
    for item in schedule["observations"]:
        row = stage8.synthetic_observation_for_tests(tmp_path, run_dir, item)
        if item["kind"] == "infeasible":
            row["TLS_invoked"] = True
            stage8.append_observation(run_dir, item["kind"], row)
            break
    result = stage8.validate_run(run_dir, write_report=False)
    assert result["validation_passed"] is False
    assert any("infeasible safety invariant" in err for err in result["validation_errors"])


def test_concurrency_aggregation_validation(config: dict[str, Any], tmp_path: Path) -> None:
    del config
    run_dir = tmp_path / "run"
    row = {
        "observation_id": "concurrency:x",
        "kind": "concurrency",
        "requested_concurrency": 4,
        "successful_sessions": 2,
        "failed_sessions": 1,
    }
    stage8.append_observation(run_dir, "concurrency", row)
    assert "concurrency aggregate mismatch: concurrency:x" in stage8._validate_concurrency(run_dir)


def test_raw_to_derived_provenance_and_checksum_verification(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_registration(tmp_path, config)
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {
            "registration_commit": kwargs.get("registration_commit"),
            "validation_passed": True,
            "validation_errors": [],
        },
    )
    run_dir = stage8.run_campaign(
        tmp_path,
        run_id="complete",
        resume=True,
        measurer=stage8.synthetic_observation_for_tests,
    )
    inventory = stage8.analyze_inventory(run_dir)
    assert inventory["counts"] == stage8.EXPECTED
    assert (tmp_path / "final" / "provenance.json").exists()
    provenance = stage8.load_json(tmp_path / "final" / "provenance.json")
    assert provenance["registration_commit"] == TEST_COMMIT
    assert provenance["campaign_design_hash"] == stage8.canonical_hash(config)
    assert provenance["registration_artifact_hash"]
    assert stage8.verify_checksums(tmp_path / "final") == []
    assert (run_dir / "RUN_COMPLETE").exists()


def test_changed_head_rejected_during_execution(
    tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_registration(tmp_path, config)
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(
        stage8, "git_commit", lambda repo: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    with pytest.raises(stage8.Stage8Error, match="registration_commit"):
        stage8.prepare_run_dir(tmp_path, "wrong-head")


def test_stage_1_to_7_evidence_preserved(config: dict[str, Any]) -> None:
    errors = stage8.verify_registered_inputs(REPO, config)
    assert errors == []


def test_default_measurement_dispatches_to_real_adapter(
    config: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scheduled = stage8.deterministic_schedule(config)["observations"][0]
    seen: dict[str, Any] = {}

    def fake_dispatch(
        repo: Path,
        run_dir: Path,
        item: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        seen["repo"] = repo
        seen["run_dir"] = run_dir
        seen["kind"] = item["kind"]
        seen["adversarial_cases"] = kwargs["adversarial_cases"]
        return {
            "observation_id": item["observation_id"],
            "kind": item["kind"],
            "completed": True,
            "final_state": "COMPLETED",
            "timing_ns": {"total_session_wall_time": 1},
            "resources": {"process_cpu_time_ns": 1},
        }

    monkeypatch.setattr(stage8, "measure_dispatch", fake_dispatch)
    row = stage8.measure_observation(tmp_path, tmp_path / "run", scheduled)
    assert row["kind"] == "feasible"
    assert seen["adversarial_cases"] == stage8.ADVERSARIAL_CASES
