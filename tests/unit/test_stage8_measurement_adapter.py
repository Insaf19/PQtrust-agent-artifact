from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.campaigns import stage8
from pqtrust_agent.campaigns import stage8_measurement as measurement
from pqtrust_agent.negotiation.stage6_scenarios import (
    INFEASIBLE_SCENARIO_IDS,
    ScenarioRegistryError,
    resolve_infeasible_scenario,
)

REPO = Path(__file__).resolve().parents[2]
TEST_COMMIT = "7c4eaf33ffc8eb74f72af9887c78ae67283a8a1f"


def test_dispatch_to_all_five_real_adapters(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    def fake(name: str):
        def inner(
            repo: Path,
            run_dir: Path,
            scheduled: dict[str, Any],
            **kwargs: Any,
        ) -> dict[str, Any]:
            del repo, run_dir, kwargs
            calls.append(name)
            return {"observation_id": scheduled["observation_id"], "kind": scheduled["kind"]}

        return inner

    monkeypatch.setattr(measurement, "measure_feasible", fake("feasible"))
    monkeypatch.setattr(measurement, "measure_infeasible", fake("infeasible"))
    monkeypatch.setattr(measurement, "measure_adversarial", fake("adversarial"))
    monkeypatch.setattr(measurement, "measure_concurrency", fake("concurrency"))
    monkeypatch.setattr(measurement, "measure_component", fake("component"))
    for kind in ("feasible", "infeasible", "adversarial", "concurrency", "component"):
        measurement.measure_dispatch(
            tmp_path,
            tmp_path,
            {"kind": kind, "observation_id": kind},
            adversarial_cases=(),
        )
    assert calls == ["feasible", "infeasible", "adversarial", "concurrency", "component"]
    with pytest.raises(measurement.MeasurementError, match="unknown observation type"):
        measurement.measure_dispatch(
            tmp_path,
            tmp_path,
            {"kind": "unknown", "observation_id": "x"},
            adversarial_cases=(),
        )


def test_placeholder_measurement_path_removed() -> None:
    source = inspect.getsource(stage8.measure_observation)
    assert "refusing to fabricate" not in source
    assert "measure_dispatch" in source


def test_null_metric_requires_unavailable_reason() -> None:
    with pytest.raises(ValueError, match="unavailable_reason"):
        measurement.validate_observation_row(
            {
                "observation_id": "obs",
                "kind": "feasible",
                "timing_ns": {"total_session_wall_time": {"value": None}},
            }
        )


def test_integer_raw_nanosecond_fields_validate() -> None:
    row = measurement.validate_observation_row(
        {
            "observation_id": "obs",
            "kind": "component",
            "component": "policy_compilation",
            "operation_count": 100,
            "batch_latency_ns": 123,
            "process_cpu_time_ns": 45,
        }
    )
    assert isinstance(row["batch_latency_ns"], int)
    assert isinstance(row["process_cpu_time_ns"], int)


def test_method_override_rejects_selection_outside_common_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Catalog:
        def profile_ids(self) -> tuple[str, ...]:
            return ("P0", "P1")

    class Compilation:
        safe_profile_ids = ("P0",)
        compilation_hash = "0" * 64

    class Scenario:
        scenario_id = "scenario"

        def scenario_hash(self) -> str:
            return "0" * 64

        task = type("Task", (), {"context_hash": lambda self: "0" * 64})()
        initiator_agent_id = "initiator"
        responder_agent_id = "responder"
        evaluation_time_utc = __import__("datetime").datetime.now(
            __import__("datetime").UTC
        )

    class Input:
        def model_dump(self, mode: str = "python") -> dict[str, Any]:
            return {}

    class ProfileCost:
        profile_id = "P0"

        def measured_vector(self, case: str) -> dict[str, Any]:
            del case
            return {"wall": __import__("decimal").Decimal("1")}

    monkeypatch.setattr(measurement, "build_selection_input", lambda **kwargs: Input())
    monkeypatch.setattr(measurement, "compute_global_anchors", lambda profiles, case: object())
    monkeypatch.setattr(measurement, "normalize_vector", lambda raw, anchors: raw)
    monkeypatch.setattr(measurement, "pareto_filter", lambda common, raw: (("P0",), {}))
    monkeypatch.setattr(measurement, "compute_regret_rows", lambda *args: ())
    monkeypatch.setattr(measurement, "minimax_regret_select", lambda rows: ("P9", ()))
    with pytest.raises(measurement.MeasurementError, match="outside common hard-safe"):
        measurement.safe_method_override(
            method="bilateral_minimax_regret",
            scenario=Scenario(),
            catalog=Catalog(),
            catalog_hash="0" * 64,
            initiator_compilation=Compilation(),
            responder_compilation=Compilation(),
            initiator_preference=object(),
            responder_preference=object(),
            cost_evidence=type(
                "Evidence",
                (),
                {
                    "profiles": [ProfileCost()],
                    "absolute_timing_stability_passed": True,
                    "paired_relative_timing_stability_passed": True,
                    "relative_cost_usable_for_selector": True,
                },
            )(),
        )


def test_component_batch_preserves_requested_operation_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stage8.write_json(
        tmp_path / "manifest.json",
        {
            "campaign_run_id": "run",
            "campaign_design_hash": "0" * 64,
            "registration_commit": "commit",
        },
    )
    calls = 0

    def op() -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(measurement, "_component_operation", lambda repo, component: op)
    row = measurement.measure_component(
        tmp_path,
        tmp_path,
        {
            "kind": "component",
            "observation_id": "component",
            "component": "policy_compilation",
            "operations": 7,
        },
    )
    assert calls == 7
    assert row["operation_count"] == 7


def test_failed_observation_is_preserved(tmp_path: Path) -> None:
    row = {
        "observation_id": "failed",
        "kind": "component",
        "completed": False,
        "component": "policy_compilation",
        "operation_count": 1,
        "batch_latency_ns": 1,
        "process_cpu_time_ns": 1,
        "classification": "measurement_failure",
        "failure_phase": "component_batch",
        "failure_code": "ERR",
        "failure_message": "failed",
    }
    stage8.append_observation(tmp_path, "component", row)
    rows = list(stage8.iter_jsonl(tmp_path / "raw" / stage8.COMPONENT_JSONL))
    assert rows[0]["completed"] is False
    assert rows[0]["failure_code"] == "ERR"


def test_changed_registration_artifact_rejected_on_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = stage8.load_yaml_config(REPO / "configs/campaigns/stage8_final_campaign.yaml")
    config_path = tmp_path / "stage8.yaml"
    config_path.write_text(__import__("yaml").safe_dump(cfg), encoding="utf-8")
    monkeypatch.setattr(stage8, "CONFIG_PATH", config_path)
    monkeypatch.setattr(stage8, "REGISTRATION_DIR", tmp_path / "registration")
    monkeypatch.setattr(stage8, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(stage8, "git_dirty", lambda repo: False)
    monkeypatch.setattr(stage8, "git_commit", lambda repo: TEST_COMMIT)
    monkeypatch.setattr(
        stage8,
        "preflight_environment",
        lambda repo, cfg, **kwargs: {"validation_passed": True, "validation_errors": []},
    )
    registration = tmp_path / "registration"
    registration.mkdir()
    design = {
        "artifact": "stage8_registered_design",
        "campaign_design_hash": stage8.canonical_hash(cfg),
        "configuration": cfg,
        "registration_commit": TEST_COMMIT,
        "registration_artifact_hash": "new",
    }
    schedule = stage8.deterministic_schedule(cfg)
    stage8.write_json(registration / "registered_design.json", design)
    stage8.write_json(registration / "execution_schedule.json", schedule)
    run_dir = tmp_path / "runs" / "run"
    run_dir.mkdir(parents=True)
    stage8.write_json(
        run_dir / "manifest.json",
        {
            "campaign_run_id": "run",
            "campaign_design_hash": stage8.canonical_hash(cfg),
            "registration_commit": TEST_COMMIT,
            "registration_artifact_hash": "old",
            "schedule_hash": schedule["schedule_hash"],
        },
    )
    with pytest.raises(stage8.Stage8Error, match="registration_artifact_hash"):
        stage8.prepare_run_dir(tmp_path, "run")


def test_technical_preflight_temp_guard_rejects_scientific_dirs() -> None:
    import importlib.util

    path = Path("scripts/validate_stage8_measurement_adapter.py").resolve()
    spec = importlib.util.spec_from_file_location("preflight", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError):
        module._assert_temp_only(Path("runs/stage8"))


@pytest.mark.parametrize("scenario_id", INFEASIBLE_SCENARIO_IDS)
def test_all_infeasible_scenario_ids_resolve(scenario_id: str) -> None:
    scenario = resolve_infeasible_scenario(REPO, scenario_id)
    assert scenario.scenario_id == scenario_id


def test_no_common_profile_does_not_resolve_through_filename_guessing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_load_scenario(path: Path) -> object:
        raise AssertionError(f"unexpected YAML scenario load: {path}")

    monkeypatch.setattr(measurement, "load_scenario", fail_load_scenario)
    fixture, constraints, cert, *_ = measurement._infeasible_chain(REPO, "no-common-profile")
    assert fixture.scenario.scenario_id == "no-common-profile"
    assert constraints
    assert cert.common_safe_set == ()


def test_unknown_infeasible_scenario_id_fails_closed() -> None:
    with pytest.raises(ScenarioRegistryError) as exc_info:
        resolve_infeasible_scenario(REPO, "missing")
    assert exc_info.value.code == "SCENARIO_ID_UNKNOWN"


def test_infeasible_resolution_independent_of_current_working_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    scenario = resolve_infeasible_scenario(REPO, "TLS-group-capability-conflict")
    assert scenario.scenario_id == "TLS-group-capability-conflict"


def test_infeasible_adapter_invokes_no_tls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    stage8.write_json(
        tmp_path / "manifest.json",
        {
            "campaign_run_id": "run",
            "campaign_design_hash": "0" * 64,
            "registration_commit": "commit",
        },
    )

    def fail_execute_tls(*args: object, **kwargs: object) -> object:
        raise AssertionError("TLS must not run for infeasible observations")

    monkeypatch.setattr(measurement, "_execute_tls", fail_execute_tls)
    row = measurement.measure_infeasible(
        REPO,
        tmp_path,
        {"kind": "infeasible", "observation_id": "inf", "scenario_id": "no-common-profile"},
    )
    assert row["completed"] is True
    assert row["TLS_invoked"] is False
    assert row["task_invoked"] is False


def _preflight_module() -> object:
    import importlib.util

    path = Path("scripts/validate_stage8_measurement_adapter.py").resolve()
    spec = importlib.util.spec_from_file_location("preflight", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _passing_preflight_rows() -> list[dict[str, Any]]:
    return [
        {
            "kind": "feasible",
            "completed": True,
            "final_state": "COMPLETED",
            "requested_tls_group": "X25519",
            "negotiated_tls_group": "x25519",
        },
        {
            "kind": "infeasible",
            "completed": True,
            "final_state": "ABORTED",
            "TLS_invoked": False,
            "task_invoked": False,
        },
        {
            "kind": "adversarial",
            "rejected": True,
            "expected_rejection_code": "REJECTED",
            "observed_rejection_code": "REJECTED",
        },
        {
            "kind": "concurrency",
            "completed": True,
            "requested_concurrency": 2,
            "successful_sessions": 2,
            "failed_sessions": 0,
        },
        {"kind": "component", "completed": True, "operation_count": 2},
    ]


def test_technical_preflight_succeeds_only_when_all_paths_pass() -> None:
    module = _preflight_module()
    assert module._preflight_invariant_errors(_passing_preflight_rows()) == []


def test_technical_preflight_fails_when_any_adapter_fails() -> None:
    module = _preflight_module()
    rows = _passing_preflight_rows()
    rows[3] = rows[3] | {"successful_sessions": 1, "failed_sessions": 1}
    assert module._preflight_invariant_errors(rows) == [
        "technical preflight invariant failed: concurrency"
    ]
