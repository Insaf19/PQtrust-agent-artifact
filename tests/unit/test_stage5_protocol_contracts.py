"""Stage 5 commit-reveal, transcript, contract, and replay tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import pqtrust_agent.protocol.commitment as commitment_module
import pqtrust_agent.protocol.replay as replay_module
import pqtrust_agent.protocol.time as protocol_time_module
import pqtrust_agent.protocol.transcript as transcript_module
from pqtrust_agent.crypto.agent_evidence_manifest import KeyLocator
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.contract import AgentContractSignature
from pqtrust_agent.models.protocol import NegotiationProposal, NegotiationReveal
from pqtrust_agent.models.selection import BilateralSelectionResult, SelectionMode
from pqtrust_agent.protocol.commitment import (
    CommitRevealSession,
    create_commitment,
    verify_commitment,
)
from pqtrust_agent.protocol.contract_builder import build_signed_contract, build_unsigned_contract
from pqtrust_agent.protocol.errors import ProtocolTimeError
from pqtrust_agent.protocol.replay import InMemoryReplayRegistry, JsonFileReplayRegistry
from pqtrust_agent.protocol.signature import algorithm_for_contract_evidence
from pqtrust_agent.protocol.transcript import build_transcript, verify_transcript
from pqtrust_agent.protocol.verification import verify_signed_contract

HASH = "a" * 64
SESSION = "1" * 64
NOW = datetime(2026, 7, 13, 0, tzinfo=UTC)


class _AcceptingSigner:
    def verify_bytes(self, payload: bytes, signature: bytes, public_key_path: Path) -> bool:
        del payload, signature, public_key_path
        return True


class _NoNowDateTime:
    @classmethod
    def now(cls, tz: Any = None) -> datetime:
        del tz
        raise AssertionError("implicit wall-clock access")

    @classmethod
    def fromisoformat(cls, value: str) -> datetime:
        return datetime.fromisoformat(value)


def _proposal(role: str = "initiator", **updates: Any) -> NegotiationProposal:
    data: dict[str, Any] = {
        "session_id": SESSION,
        "agent_id": "agent-a" if role == "initiator" else "agent-b",
        "agent_role": role,
        "scenario_hash": HASH,
        "task_hash": "b" * 64,
        "catalog_hash": "c" * 64,
        "manifest_hash": "d" * 64,
        "policy_compilation_hash": "e" * 64,
        "preference_hash": "f" * 64,
        "cost_evidence_hash": "0" * 64,
        "selector_implementation_version": "0.4.0",
        "local_safe_profile_ids": ("P0", "P1", "P3"),
        "evaluation_time": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    data.update(updates)
    return NegotiationProposal(**data)


def _reveal(
    role: str = "initiator",
    nonce: str | None = None,
    **proposal_updates: Any,
) -> NegotiationReveal:
    return NegotiationReveal(
        proposal=_proposal(role, **proposal_updates),
        nonce_hex=nonce or ("2" * 64 if role == "initiator" else "3" * 64),
    )


def _selection(**updates: Any) -> BilateralSelectionResult:
    data: dict[str, Any] = {
        "scenario_id": "test-scenario",
        "initiator_local_safe_set": ("P0", "P1", "P3"),
        "responder_local_safe_set": ("P0", "P3"),
        "common_safe_set": ("P0", "P3"),
        "pareto_frontier": ("P0", "P3"),
        "removed_as_dominated": ("P1",),
        "selected_profile_id": "P3",
        "candidates": (),
        "common_safe_candidate_count": 2,
        "pareto_candidate_count": 2,
        "selection_mode": SelectionMode.BILATERAL_MINIMAX_REGRET,
        "minimax_regret_exercised": True,
        "bilateral_tradeoff_present": True,
        "frontier_collapsed": False,
        "deterministic_tie_break_trace": ("selected P3",),
        "absolute_timing_stability_passed": False,
        "paired_relative_timing_stability_passed": True,
        "relative_cost_usable_for_selector": True,
        "selection_hash": "4" * 64,
    }
    data.update(updates)
    return BilateralSelectionResult(**data)


def _signed_contract_fixture() -> tuple[Any, Any, Any, Any, Any]:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    selection = _selection(selected_profile_id="P3")
    transcript = build_transcript(
        initiator_reveal=initiator,
        responder_reveal=responder,
        selection_result=selection,
        catalog_profile_ids=catalog.profile_ids(),
        created_at=NOW,
    )
    unsigned = build_unsigned_contract(
        transcript=transcript,
        selection_result=selection,
        catalog=catalog,
        issued_at=NOW,
        lease_seconds=60,
    )
    required = algorithm_for_contract_evidence(unsigned.contract_evidence_mode)
    sig_a = AgentContractSignature(
        agent_id="agent-a",
        role="initiator",
        key_id="a-key",
        algorithm=required,  # type: ignore[arg-type]
        public_key_sha256="5" * 64,
        signature_base64="YWJj",
    )
    sig_b = AgentContractSignature(
        agent_id="agent-b",
        role="responder",
        key_id="b-key",
        algorithm=required,  # type: ignore[arg-type]
        public_key_sha256="6" * 64,
        signature_base64="ZGVm",
    )
    signed = build_signed_contract(
        unsigned_contract=unsigned,
        initiator_signature=sig_a,
        responder_signature=sig_b,
    )
    expected_keys = {
        KeyLocator("agent-a", required): ("a-key", "5" * 64, Path("unused-a.pub")),
        KeyLocator("agent-b", required): ("b-key", "6" * 64, Path("unused-b.pub")),
    }
    return catalog, selection, transcript, signed, expected_keys


def test_proposal_validation_rejects_unsorted_duplicate_and_expired() -> None:
    with pytest.raises(ValueError, match="sorted"):
        _proposal(local_safe_profile_ids=("P1", "P0"))
    with pytest.raises(ValueError, match="unique"):
        _proposal(local_safe_profile_ids=("P0", "P0"))
    with pytest.raises(ValueError, match="later"):
        _proposal(expires_at=NOW)


def test_commitment_deterministic_and_nonce_sensitive() -> None:
    reveal = _reveal()
    assert create_commitment(reveal) == create_commitment(reveal)
    assert create_commitment(reveal) != create_commitment(_reveal(nonce="9" * 64))
    assert verify_commitment(create_commitment(reveal), reveal)


def test_reveal_mismatch_and_phase_ordering_fail_closed() -> None:
    registry = InMemoryReplayRegistry()
    session = CommitRevealSession(
        session_id=SESSION,
        activation_time=NOW,
        replay_registry=registry,
    )
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    session.register_commitment("initiator", create_commitment(initiator))
    with pytest.raises(ValueError, match="both commitments"):
        session.accept_reveal(initiator, verification_time=NOW)
    session.register_commitment("responder", create_commitment(responder))
    changed = _reveal("initiator", preference_hash="9" * 64)
    with pytest.raises(ValueError, match="does not match"):
        session.accept_reveal(changed, verification_time=NOW)


def test_commit_reveal_session_accepts_valid_pair_and_rejects_replay() -> None:
    registry = InMemoryReplayRegistry()
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    session = CommitRevealSession(
        session_id=SESSION,
        activation_time=NOW,
        replay_registry=registry,
    )
    session.register_commitment("initiator", create_commitment(initiator))
    session.register_commitment("responder", create_commitment(responder))
    session.accept_reveal(initiator, verification_time=NOW)
    session.accept_reveal(responder, verification_time=NOW)
    with pytest.raises(ValueError, match="replayed session"):
        CommitRevealSession(
            session_id=SESSION,
            activation_time=NOW,
            replay_registry=registry,
        )


def test_core_protocol_does_not_read_wall_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commitment_module, "datetime", _NoNowDateTime)
    monkeypatch.setattr(replay_module, "datetime", _NoNowDateTime)
    monkeypatch.setattr(protocol_time_module, "datetime", _NoNowDateTime)
    monkeypatch.setattr(transcript_module, "datetime", _NoNowDateTime)
    registry = InMemoryReplayRegistry()
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    session = CommitRevealSession(
        session_id=SESSION,
        activation_time=NOW,
        replay_registry=registry,
    )
    session.register_commitment("initiator", create_commitment(initiator))
    session.register_commitment("responder", create_commitment(responder))
    session.accept_reveal(initiator, verification_time=NOW)
    session.accept_reveal(responder, verification_time=NOW)
    transcript = build_transcript(
        initiator_reveal=initiator,
        responder_reveal=responder,
        selection_result=_selection(),
        catalog_profile_ids=("P0", "P1", "P2", "P3", "P4"),
        created_at=NOW,
    )
    verify_transcript(
        transcript,
        selection_result=_selection(),
        catalog_profile_ids=("P0", "P1", "P2", "P3", "P4"),
        verification_time=NOW,
        replay_registry=registry,
    )


def test_transcript_recomputes_common_safe_selection_and_hash() -> None:
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    selection = _selection()
    transcript = build_transcript(
        initiator_reveal=initiator,
        responder_reveal=responder,
        selection_result=selection,
        catalog_profile_ids=("P0", "P1", "P2", "P3", "P4"),
        created_at=NOW,
    )
    verify_transcript(
        transcript,
        selection_result=selection,
        catalog_profile_ids=("P0", "P1", "P2", "P3", "P4"),
        verification_time=NOW,
    )
    tampered = transcript.model_copy(update={"selected_profile_id": "P0"})
    with pytest.raises(ValueError, match="selected profile"):
        verify_transcript(
            tampered,
            selection_result=selection,
            catalog_profile_ids=("P0", "P1", "P2", "P3", "P4"),
            verification_time=NOW,
        )


def test_contract_binds_catalog_properties_and_lease_bounds() -> None:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    selection = _selection(
        selected_profile_id="P3",
        common_safe_set=("P0", "P3"),
        pareto_frontier=("P0", "P3"),
    )
    transcript = build_transcript(
        initiator_reveal=initiator,
        responder_reveal=responder,
        selection_result=selection,
        catalog_profile_ids=catalog.profile_ids(),
        created_at=NOW,
    )
    contract = build_unsigned_contract(
        transcript=transcript,
        selection_result=selection,
        catalog=catalog,
        issued_at=NOW,
    )
    profile = catalog.get_profile("P3")
    assert contract.tls_group == profile.tls_group
    assert contract.contract_evidence_mode == profile.contract_evidence_mode
    with pytest.raises(ValueError, match="lease exceeds"):
        build_unsigned_contract(
            transcript=transcript,
            selection_result=selection,
            catalog=catalog,
            issued_at=NOW,
            lease_seconds=profile.max_lease_seconds + 1,
        )


def test_signed_contract_hash_binds_dual_signature_metadata() -> None:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    initiator = _reveal("initiator")
    responder = _reveal("responder", local_safe_profile_ids=("P0", "P3"))
    selection = _selection(selected_profile_id="P3")
    transcript = build_transcript(
        initiator_reveal=initiator,
        responder_reveal=responder,
        selection_result=selection,
        catalog_profile_ids=catalog.profile_ids(),
        created_at=NOW,
    )
    unsigned = build_unsigned_contract(
        transcript=transcript,
        selection_result=selection,
        catalog=catalog,
        issued_at=NOW,
    )
    required = algorithm_for_contract_evidence(unsigned.contract_evidence_mode)
    sig_a = AgentContractSignature(
        agent_id="agent-a",
        role="initiator",
        key_id="a-key",
        algorithm=required,  # type: ignore[arg-type]
        public_key_sha256="5" * 64,
        signature_base64="YWJj",
    )
    sig_b = AgentContractSignature(
        agent_id="agent-b",
        role="responder",
        key_id="b-key",
        algorithm=required,  # type: ignore[arg-type]
        public_key_sha256="6" * 64,
        signature_base64="ZGVm",
    )
    signed = build_signed_contract(
        unsigned_contract=unsigned,
        initiator_signature=sig_a,
        responder_signature=sig_b,
    )
    assert signed.signed_contract_hash == signed.compute_signed_contract_hash()
    tampered = signed.model_copy(
        update={"responder_signature": sig_b.model_copy(update={"signature_base64": "ZGVmZg=="})}
    )
    assert tampered.compute_signed_contract_hash() != signed.signed_contract_hash


def test_signed_contract_verification_enforces_explicit_activation_time() -> None:
    catalog, selection, transcript, signed, expected_keys = _signed_contract_fixture()
    verify_signed_contract(
        signed,
        transcript=transcript,
        selection_result=selection,
        catalog=catalog,
        expected_keys=expected_keys,
        verification_time=NOW + timedelta(seconds=1),
        signer=_AcceptingSigner(),  # type: ignore[arg-type]
        replay_registry=InMemoryReplayRegistry(),
    )
    for verification_time, code in (
        (NOW - timedelta(seconds=1), "CONTRACT_NOT_YET_VALID"),
        (NOW + timedelta(seconds=60), "CONTRACT_EXPIRED"),
        (NOW + timedelta(seconds=61), "CONTRACT_EXPIRED"),
        (datetime(2026, 7, 13, 0), "TIMEZONE_NAIVE"),
    ):
        with pytest.raises(ProtocolTimeError) as exc_info:
            verify_signed_contract(
                signed,
                transcript=transcript,
                selection_result=selection,
                catalog=catalog,
                expected_keys=expected_keys,
                verification_time=verification_time,
                signer=_AcceptingSigner(),  # type: ignore[arg-type]
            )
        assert exc_info.value.code == code


def test_replay_registry_rejects_duplicate_commitment_and_contract_id() -> None:
    registry = InMemoryReplayRegistry()
    registry.register_session("a" * 64, reference_time=NOW)
    registry.register_commitment("a" * 64, "b" * 64, reference_time=NOW)
    with pytest.raises(ValueError, match="different session"):
        registry.register_commitment("c" * 64, "b" * 64, reference_time=NOW)
    registry.register_contract(
        contract_id="d" * 64,
        contract_hash="e" * 64,
        session_id="a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        activation_time=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="duplicate active"):
        registry.register_contract(
            contract_id="d" * 64,
            contract_hash="f" * 64,
            session_id="a" * 64,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            activation_time=NOW + timedelta(seconds=1),
        )


def test_replay_registry_contract_time_boundaries_and_naive_time() -> None:
    registry = InMemoryReplayRegistry()
    registry.register_contract(
        contract_id="d" * 64,
        contract_hash="e" * 64,
        session_id="a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        activation_time=NOW + timedelta(seconds=1),
    )
    for activation_time, code in (
        (NOW - timedelta(seconds=1), "CONTRACT_NOT_YET_VALID"),
        (NOW + timedelta(minutes=10), "CONTRACT_EXPIRED"),
        (NOW + timedelta(minutes=10, seconds=1), "CONTRACT_EXPIRED"),
        (datetime(2026, 7, 13, 0), "TIMEZONE_NAIVE"),
    ):
        with pytest.raises(ProtocolTimeError) as exc_info:
            InMemoryReplayRegistry().register_contract(
                contract_id="f" * 64,
                contract_hash="e" * 64,
                session_id="a" * 64,
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=10),
                activation_time=activation_time,
            )
        assert exc_info.value.code == code


def test_json_replay_registry_uses_supplied_time(tmp_path: Path) -> None:
    path = tmp_path / "replay.json"
    registry = JsonFileReplayRegistry(path)
    registry.register_contract(
        contract_id="d" * 64,
        contract_hash="e" * 64,
        session_id="a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        activation_time=NOW + timedelta(seconds=1),
    )
    reloaded = JsonFileReplayRegistry(path)
    with pytest.raises(ValueError, match="duplicate active"):
        reloaded.register_contract(
            contract_id="d" * 64,
            contract_hash="f" * 64,
            session_id="a" * 64,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            activation_time=NOW + timedelta(seconds=2),
        )
    reloaded.register_session("b" * 64, reference_time=NOW + timedelta(minutes=10))
    assert "d" * 64 not in reloaded.contracts


def test_canonical_hash_stability() -> None:
    proposal = _proposal()
    assert proposal.proposal_hash() == NegotiationProposal.model_validate_json(
        proposal.model_dump_json()
    ).proposal_hash()
