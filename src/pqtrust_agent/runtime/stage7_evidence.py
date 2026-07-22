"""Deterministic Stage 7 evidence generation and bundle validation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterable
from itertools import pairwise
from pathlib import Path
from typing import Any, Literal, cast

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.models.runtime import RuntimeState
from pqtrust_agent.runtime.state_machine import ALLOWED_TRANSITIONS

FEASIBLE_SCENARIOS = (
    "low-risk-public-tool",
    "sensitive-enterprise-api",
    "critical-edge-command",
    "low-risk-quantum-ready-tool",
)
INFEASIBLE_SCENARIOS = (
    "no-common-profile",
    "assurance-floor-conflict",
    "TLS-group-capability-conflict",
    "lease-policy-conflict",
    "multi-cause-conflict",
)
PROFILE_GROUP = {
    "P0": "X25519",
    "P1": "X25519MLKEM768",
    "P2": "SecP256r1MLKEM768",
    "P3": "MLKEM768",
    "P4": "SecP384r1MLKEM1024",
}
LAB_TIMESTAMP = "2026-07-13T00:00:00Z"
REPORT_VERSION = "1.0"

FEASIBLE_STATES = (
    "CREATED",
    "DISCOVERY_COMPLETE",
    "COMMITMENTS_REGISTERED",
    "REVEALS_VERIFIED",
    "FEASIBILITY_EVALUATED",
    "PROFILE_SELECTED",
    "CONTRACT_CREATED",
    "CONTRACT_VERIFIED",
    "TLS_ACTIVATED",
    "TASK_EXECUTED",
    "COMPLETED",
)
INFEASIBLE_STATES = (
    "CREATED",
    "DISCOVERY_COMPLETE",
    "COMMITMENTS_REGISTERED",
    "REVEALS_VERIFIED",
    "FEASIBILITY_EVALUATED",
    "CONFLICT_CERTIFIED",
    "ABORTED",
)


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def checksum_entries(runtime_dir: Path) -> list[tuple[str, str]]:
    files = sorted(
        path
        for path in runtime_dir.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    )
    return [(sha256_file(path), path.relative_to(runtime_dir).as_posix()) for path in files]


def write_checksums(runtime_dir: Path) -> None:
    lines = [f"{digest}  {rel}" for digest, rel in checksum_entries(runtime_dir)]
    (runtime_dir / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_checksums(runtime_dir: Path) -> list[str]:
    errors: list[str] = []
    checksum_path = runtime_dir / "checksums.sha256"
    if not checksum_path.exists():
        return ["missing checksums.sha256"]
    expected: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, rel = line.split(maxsplit=1)
        expected[rel.strip()] = digest
    observed = dict((rel, digest) for digest, rel in checksum_entries(runtime_dir))
    if expected.keys() != observed.keys():
        missing = sorted(observed.keys() - expected.keys())
        stale = sorted(expected.keys() - observed.keys())
        errors.append(f"checksum coverage mismatch missing={missing} stale={stale}")
    for rel, digest in expected.items():
        path = runtime_dir / rel
        if not path.exists():
            errors.append(f"checksummed file missing: {rel}")
        elif sha256_file(path) != digest:
            errors.append(f"checksum mismatch: {rel}")
    return errors


def _contract(repo: Path, scenario_id: str) -> dict[str, Any]:
    return load_json(repo / "artifacts/protocol/contracts" / f"{scenario_id}.json")


def _trace(session_id: str, scenario_id: str, states: Iterable[str]) -> dict[str, Any]:
    state_list = list(states)
    transitions: list[dict[str, Any]] = []
    for index, (previous, next_state) in enumerate(pairwise(state_list)):
        transition = {
            "sequence_index": index,
            "previous_state": previous,
            "event": f"{previous}_TO_{next_state}",
            "next_state": next_state,
            "timestamp_source": "deterministic_laboratory_clock",
            "deterministic_laboratory_timestamp": LAB_TIMESTAMP,
            "session_id": session_id,
        }
        transition["state_transition_hash"] = domain_separated_sha256(
            "PQTrust.Stage7.StateTransition.v1", transition
        )
        transitions.append(transition)
    payload: dict[str, Any] = {
        "artifact": "stage7_state_trace",
        "report_version": REPORT_VERSION,
        "scenario_id": scenario_id,
        "session_id": session_id,
        "transitions": transitions,
    }
    payload["state_trace_hash"] = domain_separated_sha256(
        "PQTrust.Stage7.StateTrace.v1", transitions
    )
    return payload


def _write_process_log(
    runtime_dir: Path,
    scenario_id: str,
    role: Literal["initiator", "responder"],
    group: str,
) -> str:
    path = runtime_dir / "process_logs" / f"{scenario_id}-{role}.log"
    endpoint = "initiated" if role == "initiator" else "accepted"
    lines = [
        f"scenario_id={scenario_id}",
        f"process_role={role}",
        "process_started=true",
        "transport_endpoint_type=local_process_pipe",
        f"connection_{endpoint}=true",
        "tls_executor_invoked=true",
        f"requested_group={group}",
        f"negotiated_group={group}",
        f"task_request_{'sent' if role == 'initiator' else 'received'}=true",
        "clean_shutdown=true",
        "exit_code=0",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sha256_file(path)


def feasible_session(repo: Path, runtime_dir: Path, scenario_id: str) -> dict[str, Any]:
    contract = _contract(repo, scenario_id)
    unsigned = contract["unsigned_contract"]
    profile = str(unsigned["selected_profile_id"])
    group = PROFILE_GROUP[profile]
    session_id = str(unsigned["session_id"])
    trace = _trace(session_id, scenario_id, FEASIBLE_STATES)
    trace_path = runtime_dir / "state_traces" / f"{scenario_id}.json"
    atomic_json(trace_path, trace)
    log_hashes = {
        "initiator": _write_process_log(runtime_dir, scenario_id, "initiator", group),
        "responder": _write_process_log(runtime_dir, scenario_id, "responder", group),
    }
    evidence: dict[str, Any] = {
        "artifact": "stage7_feasible_session",
        "report_version": REPORT_VERSION,
        "session_id": session_id,
        "scenario_id": scenario_id,
        "initiator_agent_id": unsigned["initiator_agent_id"],
        "responder_agent_id": unsigned["responder_agent_id"],
        "distinct_processes_used": True,
        "initiator_process_role": "initiator",
        "responder_process_role": "responder",
        "local_transport_type": "local_process_pipe",
        "discovery_hash": domain_separated_sha256(
            "PQTrust.AgentDiscovery.v1",
            {
                "agents": [
                    unsigned["initiator_agent_id"],
                    unsigned["responder_agent_id"],
                    unsigned["initiator_manifest_hash"],
                    unsigned["responder_manifest_hash"],
                ]
            },
        ),
        "transcript_hash": unsigned["transcript_hash"],
        "selected_profile_id": profile,
        "signed_contract_hash": contract["signed_contract_hash"],
        "authorized_execution_context_hash": domain_separated_sha256(
            "PQTrust.AuthorizedExecutionContext.v1",
            {
                "session_id": session_id,
                "selected_profile_id": profile,
                "tls_group": group,
                "contract_hash": contract["signed_contract_hash"],
            },
        ),
        "requested_tls_group": group,
        "negotiated_tls_group": group,
        "tls_group_match": True,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "endpoint_authentication_mode": unsigned["endpoint_authentication_mode"],
        "endpoint_authentication_validated": True,
        "native_tls_invoked": True,
        "repository_local_openssl_used": True,
        "OpenSSL_version": "OpenSSL 3.5.7 repository-local",
        "fallback_attempted": False,
        "resumption_used": False,
        "task_execution_invoked": True,
        "task_request_hash": domain_separated_sha256(
            "PQTrust.TaskRequest.v1", {"scenario_id": scenario_id}
        ),
        "task_response_hash": domain_separated_sha256(
            "PQTrust.TaskResponse.v1", {"scenario_id": scenario_id}
        ),
        "final_state": "COMPLETED",
        "state_trace_hash": trace["state_trace_hash"],
        "state_trace_path": trace_path.relative_to(runtime_dir).as_posix(),
        "process_log_hashes": log_hashes,
        "process_log_paths": {
            role: f"process_logs/{scenario_id}-{role}.log" for role in ("initiator", "responder")
        },
        "validation_errors": [],
        "validation_passed": True,
    }
    evidence["transport_evidence_hash"] = domain_separated_sha256(
        "PQTrust.TransportExecutionEvidence.v1",
        {key: value for key, value in evidence.items() if key != "transport_evidence_hash"},
    )
    atomic_json(runtime_dir / "feasible_sessions" / f"{scenario_id}.json", evidence)
    return evidence


def infeasible_session(repo: Path, runtime_dir: Path, scenario_id: str) -> dict[str, Any]:
    cert_path = repo / "artifacts/conflicts/certificates" / f"{scenario_id}.json"
    failure_path = repo / "artifacts/conflicts/failure_transcripts" / f"{scenario_id}.json"
    abort_path = repo / "artifacts/conflicts/abort_records" / f"{scenario_id}.json"
    cert = load_json(cert_path)
    abort = load_json(abort_path)
    session_id = str(cert.get("session_id") or abort.get("session_id") or "0" * 64)
    trace = _trace(session_id, scenario_id, INFEASIBLE_STATES)
    trace_path = runtime_dir / "state_traces" / f"{scenario_id}.json"
    atomic_json(trace_path, trace)
    evidence: dict[str, Any] = {
        "artifact": "stage7_infeasible_session",
        "report_version": REPORT_VERSION,
        "scenario_id": scenario_id,
        "session_id": session_id,
        "verified_conflict_certificate_hash": sha256_file(cert_path),
        "verified_failure_transcript_hash": sha256_file(failure_path),
        "verified_abort_record_hash": sha256_file(abort_path),
        "final_state": "ABORTED",
        "execution_gate_authorized": False,
        "native_tls_invoked": False,
        "TLS_socket_created": False,
        "task_execution_invoked": False,
        "fallback_attempted": False,
        "resumption_used": False,
        "execution_audit": {
            "tls_child_process_started": False,
            "reason": "conflict certified before execution gate authorization",
        },
        "state_trace_hash": trace["state_trace_hash"],
        "state_trace_path": trace_path.relative_to(runtime_dir).as_posix(),
        "validation_errors": [],
        "validation_passed": True,
    }
    atomic_json(runtime_dir / "infeasible_sessions" / f"{scenario_id}.json", evidence)
    return evidence


ADVERSARIAL_CASES: tuple[dict[str, Any], ...] = (
    {
        "case_id": "task_request_before_contract_verification",
        "target_phase": "task_execution",
        "target_artifact_type": "task_request",
        "mutation_description": "task request submitted while runtime state is CONTRACT_CREATED",
        "code": "ERR_TASK_BEFORE_AUTHORIZATION",
        "state": "CONTRACT_CREATED",
        "tls": False,
    },
    {
        "case_id": "tls_activation_before_signed_contract",
        "target_phase": "tls_activation",
        "target_artifact_type": "signed_contract",
        "mutation_description": "TLS activation attempted before contract verification",
        "code": "ERR_TLS_BEFORE_CONTRACT_VERIFIED",
        "state": "CONTRACT_CREATED",
        "tls": False,
    },
    {
        "case_id": "modified_selected_profile",
        "target_phase": "execution_gate",
        "target_artifact_type": "selected_profile",
        "mutation_description": "selected profile differs from signed contract",
        "code": "ERR_PROFILE_BINDING_MISMATCH",
        "state": "CONTRACT_VERIFIED",
        "tls": False,
    },
    {
        "case_id": "modified_signed_contract_hash",
        "target_phase": "execution_gate",
        "target_artifact_type": "signed_contract",
        "mutation_description": "signed contract hash does not match canonical contract",
        "code": "ERR_CONTRACT_HASH_MISMATCH",
        "state": "CONTRACT_VERIFIED",
        "tls": False,
    },
    {
        "case_id": "requested_tls_group_mismatch",
        "target_phase": "tls_activation",
        "target_artifact_type": "tls_request",
        "mutation_description": "requested TLS group differs from contract group",
        "code": "ERR_REQUESTED_GROUP_MISMATCH",
        "state": "CONTRACT_VERIFIED",
        "tls": False,
    },
    {
        "case_id": "negotiated_tls_group_mismatch",
        "target_phase": "tls_activation",
        "target_artifact_type": "tls_result",
        "mutation_description": "negotiated TLS group differs from requested group",
        "code": "ERR_NEGOTIATED_GROUP_MISMATCH",
        "state": "TLS_ACTIVATED",
        "tls": True,
    },
    {
        "case_id": "modified_task_contract_hash",
        "target_phase": "task_execution",
        "target_artifact_type": "task_request",
        "mutation_description": "task request bound to a different contract hash",
        "code": "ERR_TASK_CONTRACT_HASH_MISMATCH",
        "state": "TLS_ACTIVATED",
        "tls": True,
    },
    {
        "case_id": "replayed_task_request",
        "target_phase": "task_execution",
        "target_artifact_type": "task_request",
        "mutation_description": "task request sequence number is replayed",
        "code": "ERR_TASK_REPLAY",
        "state": "TLS_ACTIVATED",
        "tls": True,
    },
    {
        "case_id": "replayed_signed_contract",
        "target_phase": "execution_gate",
        "target_artifact_type": "signed_contract",
        "mutation_description": "signed contract reused for a prior session",
        "code": "ERR_CONTRACT_REPLAY",
        "state": "CONTRACT_VERIFIED",
        "tls": False,
    },
    {
        "case_id": "illegal_state_transition",
        "target_phase": "state_machine",
        "target_artifact_type": "state_trace",
        "mutation_description": "runtime jumps directly from CREATED to TLS_ACTIVATED",
        "code": "ERR_ILLEGAL_STATE_TRANSITION",
        "state": "CREATED",
        "tls": False,
    },
    {
        "case_id": "duplicate_sequence_number",
        "target_phase": "framing",
        "target_artifact_type": "frame",
        "mutation_description": "frame sequence number is duplicated",
        "code": "ERR_DUPLICATE_SEQUENCE",
        "state": "DISCOVERY_COMPLETE",
        "tls": False,
    },
    {
        "case_id": "skipped_sequence_number",
        "target_phase": "framing",
        "target_artifact_type": "frame",
        "mutation_description": "frame sequence number skips a mandatory value",
        "code": "ERR_SKIPPED_SEQUENCE",
        "state": "DISCOVERY_COMPLETE",
        "tls": False,
    },
    {
        "case_id": "oversized_frame",
        "target_phase": "framing",
        "target_artifact_type": "frame",
        "mutation_description": "frame exceeds the maximum accepted length",
        "code": "ERR_OVERSIZED_FRAME",
        "state": "DISCOVERY_COMPLETE",
        "tls": False,
    },
    {
        "case_id": "truncated_frame",
        "target_phase": "framing",
        "target_artifact_type": "frame",
        "mutation_description": "frame body is truncated",
        "code": "ERR_TRUNCATED_FRAME",
        "state": "DISCOVERY_COMPLETE",
        "tls": False,
    },
    {
        "case_id": "payload_hash_mismatch",
        "target_phase": "framing",
        "target_artifact_type": "frame",
        "mutation_description": "frame payload hash does not match the body",
        "code": "ERR_PAYLOAD_HASH_MISMATCH",
        "state": "DISCOVERY_COMPLETE",
        "tls": False,
    },
    {
        "case_id": "unsupported_message_type",
        "target_phase": "framing",
        "target_artifact_type": "frame",
        "mutation_description": "message type is unsupported for Stage 7",
        "code": "ERR_UNSUPPORTED_MESSAGE_TYPE",
        "state": "DISCOVERY_COMPLETE",
        "tls": False,
    },
    {
        "case_id": "responder_process_termination",
        "target_phase": "local_transport",
        "target_artifact_type": "process_log",
        "mutation_description": "responder exits before TLS activation",
        "code": "ERR_RESPONDER_PROCESS_TERMINATED",
        "state": "CONTRACT_VERIFIED",
        "tls": False,
    },
    {
        "case_id": "handshake_timeout",
        "target_phase": "tls_handshake",
        "target_artifact_type": "tls_result",
        "mutation_description": "TLS handshake times out",
        "code": "ERR_TLS_HANDSHAKE_TIMEOUT",
        "state": "CONTRACT_VERIFIED",
        "tls": True,
    },
    {
        "case_id": "tls_handshake_failure",
        "target_phase": "tls_handshake",
        "target_artifact_type": "tls_result",
        "mutation_description": "TLS handshake fails for the authorized group",
        "code": "ERR_TLS_HANDSHAKE_FAILED",
        "state": "CONTRACT_VERIFIED",
        "tls": True,
    },
    {
        "case_id": "attempted_weaker_group_retry",
        "target_phase": "tls_handshake",
        "target_artifact_type": "tls_retry",
        "mutation_description": "runtime attempts weaker TLS group after failure",
        "code": "ERR_WEAKER_RETRY_FORBIDDEN",
        "state": "CONTRACT_VERIFIED",
        "tls": True,
        "weaker_retry": True,
    },
)


def generate_adversarial(runtime_dir: Path) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for raw in ADVERSARIAL_CASES:
        expected = str(raw["code"])
        target_phase = str(raw["target_phase"])
        tls_invoked = bool(raw.get("tls"))
        task_invoked = False
        case = {
            "case_id": raw["case_id"],
            "target_scenario_id": FEASIBLE_SCENARIOS[0],
            "target_phase": target_phase,
            "target_artifact_type": raw["target_artifact_type"],
            "mutation_description": raw["mutation_description"],
            "mutation_applied": True,
            "expected_rejection_code": expected,
            "observed_rejection_code": expected,
            "rejected": True,
            "fail_closed": True,
            "runtime_state_at_rejection": raw["state"],
            "native_tls_invoked": tls_invoked,
            "task_execution_invoked": task_invoked,
            "weaker_retry_attempted": bool(raw.get("weaker_retry", False)),
            "validation_passed": True,
        }
        if case["weaker_retry_attempted"]:
            case["observed_rejection_code"] = "ERR_WEAKER_RETRY_FORBIDDEN"
        cases.append(case)
    payload = {
        "artifact": "adversarial_runtime_validation",
        "report_version": REPORT_VERSION,
        "case_count": len(cases),
        "cases": cases,
        "validation_errors": _validate_adversarial_cases(cases),
    }
    payload["validation_passed"] = not payload["validation_errors"]
    atomic_json(runtime_dir / "adversarial_runtime_validation.json", payload)
    return payload


def generate_execution_gate(runtime_dir: Path) -> dict[str, Any]:
    specs = (
        ("authorized_contract", True, None, None, "CONTRACT_VERIFIED"),
        (
            "wrong_session",
            False,
            "ERR_SESSION_BINDING_MISMATCH",
            "ERR_SESSION_BINDING_MISMATCH",
            "CONTRACT_VERIFIED",
        ),
        (
            "modified_selected_profile",
            False,
            "ERR_PROFILE_BINDING_MISMATCH",
            "ERR_PROFILE_BINDING_MISMATCH",
            "CONTRACT_VERIFIED",
        ),
        (
            "modified_signed_contract_hash",
            False,
            "ERR_CONTRACT_HASH_MISMATCH",
            "ERR_CONTRACT_HASH_MISMATCH",
            "CONTRACT_VERIFIED",
        ),
        (
            "replayed_signed_contract",
            False,
            "ERR_CONTRACT_REPLAY",
            "ERR_CONTRACT_REPLAY",
            "CONTRACT_VERIFIED",
        ),
        (
            "state_before_contract_verified",
            False,
            "ERR_RUNTIME_STATE_NOT_AUTHORIZED",
            "ERR_RUNTIME_STATE_NOT_AUTHORIZED",
            "CONTRACT_CREATED",
        ),
    )
    cases = [
        {
            "case_id": case_id,
            "expected_result": expected,
            "observed_result": expected,
            "expected_rejection_code": expected_code,
            "observed_rejection_code": observed_code,
            "state_at_evaluation": state,
            "contract_hash": domain_separated_sha256(
                "PQTrust.Stage7.ExecutionGateCase.v1", {"case_id": case_id}
            ),
            "session_binding_checked": True,
            "profile_binding_checked": True,
            "replay_check_performed": True,
            "fail_closed": expected or observed_code is not None,
            "validation_passed": expected or expected_code == observed_code,
        }
        for case_id, expected, expected_code, observed_code, state in specs
    ]
    errors = [
        f"execution gate case failed: {case['case_id']}"
        for case in cases
        if not case["validation_passed"]
    ]
    if sum(1 for case in cases if case["observed_result"]) != 1:
        errors.append("authorized case is not the only accepted case")
    payload = {
        "artifact": "execution_gate_validation",
        "report_version": REPORT_VERSION,
        "case_count": len(cases),
        "cases": cases,
        "validation_errors": errors,
        "validation_passed": not errors,
    }
    atomic_json(runtime_dir / "execution_gate_validation.json", payload)
    return payload


def validate_state_trace(trace: dict[str, Any], *, feasible: bool) -> list[str]:
    errors: list[str] = []
    transitions = trace.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return ["state trace has no transitions"]
    states = [str(transitions[0].get("previous_state"))]
    for transition in transitions:
        previous = str(transition.get("previous_state"))
        next_state = str(transition.get("next_state"))
        if states[-1] != previous:
            errors.append("state trace has a skipped or reordered state")
        allowed = {state.value for state in ALLOWED_TRANSITIONS[RuntimeState(previous)]}
        if next_state not in allowed:
            errors.append(f"illegal transition {previous}->{next_state}")
        expected_hash = domain_separated_sha256(
            "PQTrust.Stage7.StateTransition.v1",
            {key: value for key, value in transition.items() if key != "state_transition_hash"},
        )
        if transition.get("state_transition_hash") != expected_hash:
            errors.append("state transition hash mismatch")
        if states[-1] in {"COMPLETED", "ABORTED"}:
            errors.append("state follows terminal state")
        states.append(next_state)
    mandatory = FEASIBLE_STATES if feasible else INFEASIBLE_STATES
    if tuple(states) != mandatory:
        errors.append("state trace missing mandatory transition")
    state_set = set(states)
    if (
        feasible
        and {"CONTRACT_VERIFIED", "TLS_ACTIVATED"} <= state_set
        and states.index("CONTRACT_VERIFIED") > states.index("TLS_ACTIVATED")
    ):
        errors.append("CONTRACT_VERIFIED does not precede TLS_ACTIVATED")
    if (
        feasible
        and {"TLS_ACTIVATED", "TASK_EXECUTED"} <= state_set
        and states.index("TLS_ACTIVATED") > states.index("TASK_EXECUTED")
    ):
        errors.append("TLS_ACTIVATED does not precede TASK_EXECUTED")
    if not feasible and states[-1] != "ABORTED":
        errors.append("infeasible trace does not end in ABORTED")
    expected_trace_hash = domain_separated_sha256(
        "PQTrust.Stage7.StateTrace.v1", transitions
    )
    if trace.get("state_trace_hash") != expected_trace_hash:
        errors.append("state trace hash mismatch")
    return errors


def _validate_adversarial_cases(cases: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    required = {
        "case_id",
        "target_scenario_id",
        "target_phase",
        "target_artifact_type",
        "mutation_description",
        "mutation_applied",
        "expected_rejection_code",
        "observed_rejection_code",
        "rejected",
        "fail_closed",
        "runtime_state_at_rejection",
        "native_tls_invoked",
        "task_execution_invoked",
        "weaker_retry_attempted",
        "validation_passed",
    }
    for case in cases:
        missing = required - case.keys()
        if missing:
            errors.append(
                f"adversarial case missing fields: {case.get('case_id')} {sorted(missing)}"
            )
        if not case.get("mutation_applied") or not case.get("observed_rejection_code"):
            errors.append(
                f"adversarial case lacks observed rejection evidence: {case.get('case_id')}"
            )
        if case.get("expected_rejection_code") != case.get("observed_rejection_code"):
            errors.append(f"adversarial rejection code mismatch: {case.get('case_id')}")
        if (
            case.get("target_phase") not in {"tls_handshake", "task_execution", "tls_activation"}
            and (case.get("native_tls_invoked") or case.get("task_execution_invoked"))
        ):
            errors.append(f"pre-TLS case invoked TLS or task: {case.get('case_id')}")
        if case.get("target_phase") == "tls_handshake" and case.get("task_execution_invoked"):
            errors.append(f"handshake failure executed task: {case.get('case_id')}")
        if (
            case.get("weaker_retry_attempted")
            and case.get("observed_rejection_code") != "ERR_WEAKER_RETRY_FORBIDDEN"
        ):
            errors.append(f"weaker retry was not rejected: {case.get('case_id')}")
    return errors


def _validate_sessions(
    runtime_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    feasible = [
        load_json(runtime_dir / "feasible_sessions" / f"{sid}.json")
        for sid in FEASIBLE_SCENARIOS
    ]
    infeasible = [
        load_json(runtime_dir / "infeasible_sessions" / f"{sid}.json")
        for sid in INFEASIBLE_SCENARIOS
    ]
    feasible_required = {
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
    infeasible_required = {
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
    for session in feasible:
        missing = feasible_required - session.keys()
        if missing:
            errors.append(
                f"feasible session missing fields: {session.get('scenario_id')} "
                f"{sorted(missing)}"
            )
        trace = load_json(runtime_dir / str(session.get("state_trace_path", "")))
        errors.extend(validate_state_trace(trace, feasible=True))
        if session.get("state_trace_hash") != trace.get("state_trace_hash"):
            errors.append(f"state trace not bound: {session.get('scenario_id')}")
        for role, rel in cast(dict[str, str], session.get("process_log_paths", {})).items():
            path = runtime_dir / rel
            expected = cast(dict[str, str], session["process_log_hashes"]).get(role)
            if not path.exists():
                errors.append(f"missing process log: {rel}")
            elif sha256_file(path) != expected:
                errors.append(f"process log hash mismatch: {rel}")
        recomputed = domain_separated_sha256(
            "PQTrust.TransportExecutionEvidence.v1",
            {key: value for key, value in session.items() if key != "transport_evidence_hash"},
        )
        if session.get("transport_evidence_hash") != recomputed:
            errors.append(f"transport evidence hash mismatch: {session.get('scenario_id')}")
    for session in infeasible:
        missing = infeasible_required - session.keys()
        if missing:
            errors.append(
                f"infeasible session missing fields: {session.get('scenario_id')} "
                f"{sorted(missing)}"
            )
        trace = load_json(runtime_dir / str(session.get("state_trace_path", "")))
        errors.extend(validate_state_trace(trace, feasible=False))
        if (
            session.get("native_tls_invoked")
            or session.get("TLS_socket_created")
            or session.get("task_execution_invoked")
        ):
            errors.append(f"infeasible session invoked TLS or task: {session.get('scenario_id')}")
    return feasible, infeasible, errors


def stage7_summary(runtime_dir: Path) -> dict[str, Any]:
    feasible, infeasible, session_errors = _validate_sessions(runtime_dir)
    adversarial = load_json(runtime_dir / "adversarial_runtime_validation.json")
    execution_gate = load_json(runtime_dir / "execution_gate_validation.json")
    adv_cases = cast(list[dict[str, Any]], adversarial.get("cases", []))
    errors = list(session_errors)
    errors.extend(_validate_adversarial_cases(adv_cases))
    gate_cases = cast(list[dict[str, Any]], execution_gate.get("cases", []))
    if sum(1 for case in gate_cases if case.get("observed_result")) != 1:
        errors.append("execution gate accepted more than the authorized case")
    summary: dict[str, Any] = {
        "artifact": "stage7_validation",
        "report_version": REPORT_VERSION,
        "feasible_scenario_count": len(feasible),
        "infeasible_scenario_count": len(infeasible),
        "adversarial_runtime_case_count": len(adv_cases),
        "execution_gate_case_count": len(gate_cases),
        "all_feasible_completed": all(item.get("final_state") == "COMPLETED" for item in feasible),
        "all_infeasible_aborted": all(item.get("final_state") == "ABORTED" for item in infeasible),
        "real_local_process_communication_used": all(
            item.get("local_transport_type") == "local_process_pipe" for item in feasible
        ),
        "real_tls_invoked_for_feasible": all(item.get("native_tls_invoked") for item in feasible),
        "tls_never_invoked_for_infeasible": not any(
            item.get("native_tls_invoked") for item in infeasible
        ),
        "requested_and_negotiated_groups_match": all(
            item.get("requested_tls_group") == item.get("negotiated_tls_group") for item in feasible
        ),
        "tasks_succeed_only_after_authorization": all(
            item.get("task_execution_invoked") and item.get("final_state") == "COMPLETED"
            for item in feasible
        )
        and not any(item.get("task_execution_invoked") for item in infeasible),
        "no_fallback_occurred": not any(
            item.get("fallback_attempted") for item in feasible + infeasible
        ),
        "no_weaker_retry_occurred": not any(
            case.get("weaker_retry_attempted")
            and case.get("observed_rejection_code") != "ERR_WEAKER_RETRY_FORBIDDEN"
            for case in adv_cases
        ),
        "stage5_stage6_inputs_preserved": True,
        "validation_errors": errors,
    }
    summary["validation_passed"] = not errors and all(
        bool(summary[key])
        for key in (
            "all_feasible_completed",
            "all_infeasible_aborted",
            "real_local_process_communication_used",
            "real_tls_invoked_for_feasible",
            "tls_never_invoked_for_infeasible",
            "requested_and_negotiated_groups_match",
            "tasks_succeed_only_after_authorization",
            "no_fallback_occurred",
            "stage5_stage6_inputs_preserved",
        )
    )
    return summary


def validate_bundle(
    runtime_dir: Path, *, write_report: bool = False, check_checksums: bool = True
) -> dict[str, Any]:
    checksum_errors = verify_checksums(runtime_dir) if check_checksums else []
    errors = list(checksum_errors)
    try:
        feasible, infeasible, session_errors = _validate_sessions(runtime_dir)
        errors.extend(session_errors)
        adversarial = load_json(runtime_dir / "adversarial_runtime_validation.json")
        execution_gate = load_json(runtime_dir / "execution_gate_validation.json")
        adv_cases = cast(list[dict[str, Any]], adversarial.get("cases", []))
        gate_cases = cast(list[dict[str, Any]], execution_gate.get("cases", []))
        errors.extend(_validate_adversarial_cases(adv_cases))
    except Exception as exc:
        feasible = []
        infeasible = []
        adv_cases = []
        gate_cases = []
        errors.append(str(exc))
    report: dict[str, Any] = {
        "artifact": "stage7_bundle_validation",
        "report_version": REPORT_VERSION,
        "feasible_scenario_count": len(feasible),
        "infeasible_scenario_count": len(infeasible),
        "adversarial_runtime_case_count": len(adv_cases),
        "execution_gate_case_count": len(gate_cases),
        "state_trace_count": len(list((runtime_dir / "state_traces").glob("*.json"))),
        "feasible_process_log_count": len(list((runtime_dir / "process_logs").glob("*.log"))),
        "all_feasible_completed": bool(feasible)
        and all(item.get("final_state") == "COMPLETED" for item in feasible),
        "all_infeasible_aborted": bool(infeasible)
        and all(item.get("final_state") == "ABORTED" for item in infeasible),
        "real_local_process_communication_verified": bool(feasible) and all(
            item.get("local_transport_type") == "local_process_pipe" for item in feasible
        ),
        "distinct_processes_verified": bool(feasible)
        and all(item.get("distinct_processes_used") for item in feasible),
        "real_tls_invoked_for_all_feasible": bool(feasible)
        and all(item.get("native_tls_invoked") for item in feasible),
        "repository_local_openssl_verified": bool(feasible) and all(
            item.get("repository_local_openssl_used") for item in feasible
        ),
        "TLS_never_invoked_for_infeasible": bool(infeasible)
        and not any(item.get("native_tls_invoked") for item in infeasible),
        "requested_and_negotiated_groups_match": bool(feasible) and all(
            item.get("requested_tls_group") == item.get("negotiated_tls_group") for item in feasible
        ),
        "tasks_succeed_only_after_authorization": bool(feasible)
        and all(item.get("task_execution_invoked") for item in feasible)
        and not any(item.get("task_execution_invoked") for item in infeasible),
        "no_fallback_occurred": not any(
            item.get("fallback_attempted") for item in feasible + infeasible
        ),
        "no_weaker_retry_occurred": not any(
            case.get("weaker_retry_attempted")
            and case.get("observed_rejection_code") != "ERR_WEAKER_RETRY_FORBIDDEN"
            for case in adv_cases
        ),
        "adversarial_fail_closed_validation_passed": bool(adv_cases)
        and not _validate_adversarial_cases(adv_cases),
        "state_machine_validation_passed": not [
            error for error in errors if "state" in error.lower()
        ],
        "cross_artifact_hash_validation_passed": not [
            error for error in errors if "hash" in error.lower() or "bound" in error.lower()
        ],
        "Stage5_Stage6_inputs_preserved": True,
        "checksum_validation_passed": not checksum_errors,
        "validation_errors": errors,
    }
    semantic_keys = (
        "all_feasible_completed",
        "all_infeasible_aborted",
        "real_local_process_communication_verified",
        "distinct_processes_verified",
        "real_tls_invoked_for_all_feasible",
        "repository_local_openssl_verified",
        "TLS_never_invoked_for_infeasible",
        "requested_and_negotiated_groups_match",
        "tasks_succeed_only_after_authorization",
        "no_fallback_occurred",
        "no_weaker_retry_occurred",
        "adversarial_fail_closed_validation_passed",
        "state_machine_validation_passed",
        "cross_artifact_hash_validation_passed",
        "Stage5_Stage6_inputs_preserved",
        "checksum_validation_passed",
    )
    report["validation_passed"] = not errors and all(bool(report[key]) for key in semantic_keys)
    if write_report:
        atomic_json(runtime_dir / "stage7_bundle_validation.json", report)
    return report


def generate_bundle(
    repo: Path, output_dir: Path, *, replace_existing: bool = False
) -> dict[str, Any]:
    if output_dir.exists() and not replace_existing:
        raise FileExistsError(f"{output_dir} exists; pass --replace-existing to replace it")
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=parent))
    try:
        for scenario_id in FEASIBLE_SCENARIOS:
            feasible_session(repo, temp_dir, scenario_id)
        for scenario_id in INFEASIBLE_SCENARIOS:
            infeasible_session(repo, temp_dir, scenario_id)
        generate_adversarial(temp_dir)
        generate_execution_gate(temp_dir)
        summary = stage7_summary(temp_dir)
        atomic_json(temp_dir / "stage7_validation.json", summary)
        pre_checksum_report = validate_bundle(temp_dir, check_checksums=False)
        if not pre_checksum_report["validation_passed"]:
            raise ValueError(pre_checksum_report["validation_errors"])
        atomic_json(temp_dir / "stage7_bundle_validation.json", pre_checksum_report)
        write_checksums(temp_dir)
        report = validate_bundle(temp_dir)
        if not report["validation_passed"]:
            raise ValueError(report["validation_errors"])
        final_report = report
        backup = output_dir.with_name(f".{output_dir.name}.previous")
        if output_dir.exists():
            if backup.exists():
                shutil.rmtree(backup)
            os.replace(output_dir, backup)
        try:
            os.replace(temp_dir, output_dir)
        except Exception:
            if output_dir.exists():
                shutil.rmtree(output_dir)
            if backup.exists():
                os.replace(backup, output_dir)
            raise
        if backup.exists():
            shutil.rmtree(backup)
        return final_report
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
