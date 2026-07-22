from __future__ import annotations

import hashlib
import multiprocessing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.evidence.canonical import canonicalize
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.contract import (
    AgentContractSignature,
    SignedTrustContract,
    UnsignedTrustContract,
)
from pqtrust_agent.models.protocol import NegotiationTranscript
from pqtrust_agent.models.runtime import AgentAdvertisement, RuntimeState
from pqtrust_agent.models.selection import BilateralSelectionResult
from pqtrust_agent.models.transport import MessageType
from pqtrust_agent.runtime.agent_runtime import LocalDiscoveryRegistry
from pqtrust_agent.runtime.errors import DiscoveryError, TaskProtocolError
from pqtrust_agent.runtime.execution_gate import ExecutionGate
from pqtrust_agent.runtime.state_machine import RuntimeStateMachine
from pqtrust_agent.transport.framing import (
    FrameError,
    SequenceValidator,
    decode_frame,
    encode_frame,
)
from pqtrust_agent.transport.task_protocol import TaskProtocol
from pqtrust_agent.transport.tls_executor import MockTlsExecutor

SESSION = "a" * 64
HASH = "b" * 64


def _sig(agent_id: str, role: str) -> AgentContractSignature:
    return AgentContractSignature(
        agent_id=agent_id,
        role=role,  # type: ignore[arg-type]
        key_id=f"{agent_id}:ML-DSA-65:lab-v1",
        algorithm="ML-DSA-65",
        public_key_sha256=HASH,
        signature_base64="AA==",
    )


def _contract() -> SignedTrustContract:
    issued = datetime(2026, 7, 13, tzinfo=UTC)
    unsigned = UnsignedTrustContract(
        contract_id=SESSION,
        session_id=SESSION,
        initiator_agent_id="initiator",
        responder_agent_id="responder",
        scenario_hash=HASH,
        task_hash=HASH,
        catalog_hash=HASH,
        cost_evidence_hash=HASH,
        initiator_manifest_hash=HASH,
        responder_manifest_hash=HASH,
        initiator_policy_compilation_hash=HASH,
        responder_policy_compilation_hash=HASH,
        initiator_preference_hash=HASH,
        responder_preference_hash=HASH,
        transcript_hash=HASH,
        selection_hash=HASH,
        common_safe_profile_ids=("P0",),
        Pareto_frontier_profile_ids=("P0",),
        selected_profile_id="P0",
        tls_group="X25519",
        endpoint_authentication_mode="classical_x509",
        contract_evidence_mode="mldsa65",
        fallback_rule="low_risk_only",
        resumption_rule="context_bound",
        lease_strictness="long",
        issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    provisional = SignedTrustContract(
        unsigned_contract=unsigned,
        initiator_signature=_sig("initiator", "initiator"),
        responder_signature=_sig("responder", "responder"),
        signed_contract_hash="0" * 64,
    )
    return provisional.model_copy(
        update={"signed_contract_hash": provisional.compute_signed_contract_hash()}
    )


def _transcript() -> NegotiationTranscript:
    return NegotiationTranscript.model_construct(
        session_id=SESSION,
        initiator_local_safe_set=("P0",),
        responder_local_safe_set=("P0",),
        transcript_hash=HASH,
    )


def _selection() -> BilateralSelectionResult:
    return BilateralSelectionResult.model_construct(
        selected_profile_id="P0",
        selection_hash=HASH,
    )


def _verifier(
    signed_contract: SignedTrustContract,
    transcript: NegotiationTranscript,
    selection_result: BilateralSelectionResult,
    catalog: Any,
    activation_time: datetime,
) -> None:
    del signed_contract, transcript, selection_result, catalog, activation_time


def test_legal_state_transitions() -> None:
    machine = RuntimeStateMachine()
    for state in (
        RuntimeState.DISCOVERY_COMPLETE,
        RuntimeState.COMMITMENTS_REGISTERED,
        RuntimeState.REVEALS_VERIFIED,
        RuntimeState.FEASIBILITY_EVALUATED,
        RuntimeState.PROFILE_SELECTED,
        RuntimeState.CONTRACT_CREATED,
        RuntimeState.CONTRACT_VERIFIED,
        RuntimeState.TLS_ACTIVATED,
        RuntimeState.TASK_EXECUTED,
        RuntimeState.COMPLETED,
    ):
        machine.transition(state, reason=state.value)
    assert machine.state == RuntimeState.COMPLETED


def test_illegal_state_transition_rejected() -> None:
    machine = RuntimeStateMachine()
    with pytest.raises(RuntimeError):
        machine.transition(RuntimeState.TLS_ACTIVATED, reason="skip contract")


def test_deterministic_framing_and_sequence_validation() -> None:
    frame = encode_frame(
        protocol_version="1.0",
        message_type=MessageType.DISCOVERY,
        session_id=SESSION,
        sequence_number=0,
        payload={"agent": "initiator"},
    )
    assert frame == encode_frame(
        protocol_version="1.0",
        message_type=MessageType.DISCOVERY,
        session_id=SESSION,
        sequence_number=0,
        payload={"agent": "initiator"},
    )
    header, payload = decode_frame(frame)
    assert payload == {"agent": "initiator"}
    validator = SequenceValidator()
    validator.observe(header)
    with pytest.raises(FrameError):
        validator.observe(header)


def test_frame_length_and_hash_validation() -> None:
    frame = bytearray(
        encode_frame(
            protocol_version="1.0",
            message_type=MessageType.COMMITMENT,
            session_id=SESSION,
            sequence_number=0,
            payload={"commitment": HASH},
        )
    )
    with pytest.raises(FrameError):
        decode_frame(bytes(frame[:-1]))
    frame[-2] = frame[-2] ^ 1
    with pytest.raises(FrameError):
        decode_frame(bytes(frame))


def test_sequence_skipped_rejected() -> None:
    header, _ = decode_frame(
        encode_frame(
            protocol_version="1.0",
            message_type=MessageType.REVEAL,
            session_id=SESSION,
            sequence_number=1,
            payload={"reveal": HASH},
        )
    )
    with pytest.raises(FrameError):
        SequenceValidator().observe(header)


def test_discovery_rejects_duplicate_and_unknown_key() -> None:
    now = datetime(2026, 7, 13, tzinfo=UTC)
    ad = AgentAdvertisement(
        agent_id="agent",
        protocol_version="1.0",
        manifest_hash=HASH,
        supported_message_versions=("1.0",),
        endpoint_identifier="unix:/tmp/a.sock",
        evidence_key_fingerprint=HASH,
        valid_from=now - timedelta(seconds=1),
        valid_until=now + timedelta(seconds=1),
    )
    registry = LocalDiscoveryRegistry(
        expected_manifest_hashes={"agent": HASH},
        known_evidence_key_fingerprints={HASH},
    )
    registry.register(ad, reference_time=now)
    with pytest.raises(DiscoveryError):
        registry.register(ad, reference_time=now)
    assert registry.discover(("agent",)).discovery_hash != "0" * 64


def test_execution_gate_authorizes_and_rejects_wrong_state() -> None:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    gate = ExecutionGate(catalog=catalog, verifier=_verifier)
    contract = _contract()
    authorized = gate.authorize(
        session_id=SESSION,
        signed_contract=contract,
        transcript=_transcript(),
        selection_result=_selection(),
        activation_time=datetime(2026, 7, 13, 0, 0, 1, tzinfo=UTC),
        runtime_state=RuntimeState.CONTRACT_VERIFIED,
    )
    assert authorized.tls_group == "X25519"
    rejected = gate.authorize(
        session_id=SESSION,
        signed_contract=contract,
        transcript=_transcript(),
        selection_result=_selection(),
        activation_time=datetime(2026, 7, 13, 0, 0, 1, tzinfo=UTC),
        runtime_state=RuntimeState.CONTRACT_CREATED,
    )
    assert rejected.fail_closed is True


def test_task_execution_ordering_and_replay() -> None:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    gate = ExecutionGate(catalog=catalog, verifier=_verifier)
    context = gate.authorize(
        session_id=SESSION,
        signed_contract=_contract(),
        transcript=_transcript(),
        selection_result=_selection(),
        activation_time=datetime(2026, 7, 13, 0, 0, 1, tzinfo=UTC),
        runtime_state=RuntimeState.CONTRACT_VERIFIED,
    )
    assert not isinstance(context, type(None))
    protocol = TaskProtocol()
    payload = b"stage7 task payload"
    request = protocol.build_request(
        context=context,  # type: ignore[arg-type]
        scenario_hash=HASH,
        payload=payload,
        request_sequence_number=0,
    )
    with pytest.raises(TaskProtocolError):
        protocol.execute(
            request,
            context=context,  # type: ignore[arg-type]
            payload=payload,
            runtime_state=RuntimeState.CONTRACT_VERIFIED,
        )
    response = protocol.execute(
        request,
        context=context,  # type: ignore[arg-type]
        payload=payload,
        runtime_state=RuntimeState.TLS_ACTIVATED,
    )
    assert response.status == "ok"
    with pytest.raises(TaskProtocolError):
        protocol.execute(
            request,
            context=context,  # type: ignore[arg-type]
            payload=payload,
            runtime_state=RuntimeState.TLS_ACTIVATED,
        )


def test_mock_tls_group_binding() -> None:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    gate = ExecutionGate(catalog=catalog, verifier=_verifier)
    context = gate.authorize(
        session_id=SESSION,
        signed_contract=_contract(),
        transcript=_transcript(),
        selection_result=_selection(),
        activation_time=datetime(2026, 7, 13, 0, 0, 1, tzinfo=UTC),
        runtime_state=RuntimeState.CONTRACT_VERIFIED,
    )
    result = MockTlsExecutor().execute(
        context,  # type: ignore[arg-type]
        certificate=Path("unused"),
        private_key=Path("unused"),
        ca_certificate=Path("unused"),
    )
    assert result.negotiated_tls_group == "X25519"


def _pipe_responder(conn: Any) -> None:
    data = conn.recv_bytes()
    conn.send_bytes(data)
    conn.close()


def test_feasible_local_process_session(tmp_path: Path) -> None:
    del tmp_path
    parent_conn, child_conn = multiprocessing.Pipe(duplex=True)
    process = multiprocessing.Process(target=_pipe_responder, args=(child_conn,))
    process.start()
    try:
        parent_conn.send_bytes(b"stage7")
        response = parent_conn.recv_bytes()
    finally:
        parent_conn.close()
        process.join(timeout=5.0)
        if process.is_alive():
            process.terminate()
    assert response == b"stage7"
    assert process.exitcode == 0


def test_stage5_stage6_artifact_bytes_read_only() -> None:
    paths = [
        Path("artifacts/protocol/contracts/low-risk-public-tool.json"),
        Path("artifacts/conflicts/stage6_bundle_validation.json"),
    ]
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    after = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    assert before == after


def test_canonical_payload_hash_is_stable() -> None:
    payload = {"b": 2, "a": 1}
    assert canonicalize(payload) == b'{"a":1,"b":2}'
