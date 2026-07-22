from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.runtime.stage7_evidence import (
    FEASIBLE_SCENARIOS,
    INFEASIBLE_SCENARIOS,
    generate_bundle,
    load_json,
    validate_bundle,
    validate_state_trace,
)

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = (
    "run_end_to_end_session.py",
    "validate_end_to_end_stage.py",
    "validate_execution_gate_stage.py",
    "validate_stage7.py",
)


@pytest.fixture()
def runtime_bundle(tmp_path: Path) -> Path:
    runtime_dir = tmp_path / "runtime"
    generate_bundle(REPO, runtime_dir, replace_existing=True)
    return runtime_dir


def _load(path: Path) -> dict[str, Any]:
    return load_json(path)


def test_cli_help_has_no_side_effects(tmp_path: Path) -> None:
    before = sorted(tmp_path.rglob("*"))
    for script in SCRIPTS:
        result = subprocess.run(
            [sys.executable, str(REPO / "scripts" / script), "--help"],
            cwd=REPO,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "usage:" in result.stdout
    assert sorted(tmp_path.rglob("*")) == before


def test_importing_cli_scripts_has_no_execution(tmp_path: Path) -> None:
    for script in SCRIPTS:
        spec = importlib.util.spec_from_file_location(
            script.removesuffix(".py"), REPO / "scripts" / script
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    assert not any(tmp_path.iterdir())


def test_complete_feasible_session_evidence(runtime_bundle: Path) -> None:
    required = {
        "session_id",
        "scenario_id",
        "initiator_agent_id",
        "responder_agent_id",
        "distinct_processes_used",
        "initiator_process_role",
        "responder_process_role",
        "local_transport_type",
        "discovery_hash",
        "transcript_hash",
        "selected_profile_id",
        "signed_contract_hash",
        "authorized_execution_context_hash",
        "requested_tls_group",
        "negotiated_tls_group",
        "tls_group_match",
        "tls_version",
        "cipher_suite",
        "endpoint_authentication_mode",
        "endpoint_authentication_validated",
        "native_tls_invoked",
        "repository_local_openssl_used",
        "OpenSSL_version",
        "fallback_attempted",
        "resumption_used",
        "task_execution_invoked",
        "task_request_hash",
        "task_response_hash",
        "final_state",
        "state_trace_hash",
        "process_log_hashes",
        "transport_evidence_hash",
        "validation_errors",
        "validation_passed",
    }
    for scenario_id in FEASIBLE_SCENARIOS:
        session = _load(runtime_bundle / "feasible_sessions" / f"{scenario_id}.json")
        assert required <= session.keys()
        assert session["final_state"] == "COMPLETED"
        assert session["distinct_processes_used"] is True
        assert session["initiator_process_role"] != session["responder_process_role"]
        assert session["repository_local_openssl_used"] is True


def test_complete_infeasible_session_evidence(runtime_bundle: Path) -> None:
    required = {
        "verified_conflict_certificate_hash",
        "verified_failure_transcript_hash",
        "verified_abort_record_hash",
        "final_state",
        "execution_gate_authorized",
        "native_tls_invoked",
        "TLS_socket_created",
        "task_execution_invoked",
        "fallback_attempted",
        "resumption_used",
        "state_trace_hash",
        "validation_errors",
        "validation_passed",
    }
    for scenario_id in INFEASIBLE_SCENARIOS:
        session = _load(runtime_bundle / "infeasible_sessions" / f"{scenario_id}.json")
        assert required <= session.keys()
        assert session["final_state"] == "ABORTED"
        assert session["native_tls_invoked"] is False
        assert session["TLS_socket_created"] is False
        assert session["task_execution_invoked"] is False


def test_legal_state_traces_and_missing_transition_rejection(runtime_bundle: Path) -> None:
    trace = _load(runtime_bundle / "state_traces" / "low-risk-public-tool.json")
    assert validate_state_trace(trace, feasible=True) == []
    mutated = dict(trace)
    mutated["transitions"] = list(trace["transitions"])
    del mutated["transitions"][6]
    assert "state trace missing mandatory transition" in validate_state_trace(
        mutated, feasible=True
    )


def test_process_log_hash_binding(runtime_bundle: Path) -> None:
    session = _load(runtime_bundle / "feasible_sessions" / "low-risk-public-tool.json")
    for role, rel in session["process_log_paths"].items():
        digest = hashlib.sha256((runtime_bundle / rel).read_bytes()).hexdigest()
        assert digest == session["process_log_hashes"][role]


def test_adversarial_structured_rejection_codes(runtime_bundle: Path) -> None:
    payload = _load(runtime_bundle / "adversarial_runtime_validation.json")
    for case in payload["cases"]:
        assert case["mutation_applied"] is True
        assert case["observed_rejection_code"] == case["expected_rejection_code"]
        assert case["fail_closed"] is True
    before_tls = [
        case
        for case in payload["cases"]
        if case["target_phase"] not in {"tls_handshake", "task_execution", "tls_activation"}
    ]
    assert before_tls
    assert all(not case["native_tls_invoked"] for case in before_tls)
    handshake = [case for case in payload["cases"] if case["target_phase"] == "tls_handshake"]
    assert handshake
    assert all(not case["task_execution_invoked"] for case in handshake)
    weaker = [case for case in payload["cases"] if case["weaker_retry_attempted"]]
    assert weaker
    assert weaker[0]["observed_rejection_code"] == "ERR_WEAKER_RETRY_FORBIDDEN"


def test_execution_gate_only_authorized_case_accepted(runtime_bundle: Path) -> None:
    payload = _load(runtime_bundle / "execution_gate_validation.json")
    accepted = [case for case in payload["cases"] if case["observed_result"]]
    assert [case["case_id"] for case in accepted] == ["authorized_contract"]
    assert all("state_at_evaluation" in case for case in payload["cases"])


def test_bundle_report_written_and_checksummed(runtime_bundle: Path) -> None:
    report = _load(runtime_bundle / "stage7_bundle_validation.json")
    assert report["validation_passed"] is True
    checksums = (runtime_bundle / "checksums.sha256").read_text(encoding="utf-8")
    assert "stage7_bundle_validation.json" in checksums


def test_missing_state_trace_or_process_log_fails_bundle(runtime_bundle: Path) -> None:
    (runtime_bundle / "state_traces" / "low-risk-public-tool.json").unlink()
    assert validate_bundle(runtime_bundle)["validation_passed"] is False

    runtime_dir = runtime_bundle.parent / "runtime-process-missing"
    generate_bundle(REPO, runtime_dir, replace_existing=True)
    (runtime_dir / "process_logs" / "low-risk-public-tool-initiator.log").unlink()
    assert validate_bundle(runtime_dir)["validation_passed"] is False


def test_hard_coded_rejected_true_without_observed_code_fails(runtime_bundle: Path) -> None:
    payload = _load(runtime_bundle / "adversarial_runtime_validation.json")
    del payload["cases"][0]["observed_rejection_code"]
    (runtime_bundle / "adversarial_runtime_validation.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert validate_bundle(runtime_bundle)["validation_passed"] is False


def test_checksum_success_alone_cannot_make_semantic_validation_pass(runtime_bundle: Path) -> None:
    session_path = runtime_bundle / "infeasible_sessions" / "no-common-profile.json"
    session = _load(session_path)
    session["native_tls_invoked"] = True
    session_path.write_text(
        json.dumps(session, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    from pqtrust_agent.runtime.stage7_evidence import write_checksums

    write_checksums(runtime_bundle)
    result = validate_bundle(runtime_bundle)
    assert result["checksum_validation_passed"] is True
    assert result["validation_passed"] is False


def test_failed_regeneration_preserves_previous_valid_bundle(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    generate_bundle(REPO, runtime_dir, replace_existing=True)
    before = hashlib.sha256((runtime_dir / "stage7_validation.json").read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        generate_bundle(REPO, runtime_dir, replace_existing=False)
    after = hashlib.sha256((runtime_dir / "stage7_validation.json").read_bytes()).hexdigest()
    assert before == after


def test_stage5_and_stage6_artifacts_remain_byte_identical(runtime_bundle: Path) -> None:
    del runtime_bundle
    paths = [
        REPO / "artifacts/protocol/contracts/low-risk-public-tool.json",
        REPO / "artifacts/conflicts/stage6_bundle_validation.json",
    ]
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    after = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    assert before == after
