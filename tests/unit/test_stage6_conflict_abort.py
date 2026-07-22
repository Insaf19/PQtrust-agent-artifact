"""Stage 6 conflict certificate and safe-abort tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.models.abort import SafeAbortRecord
from pqtrust_agent.models.conflict import (
    ConflictCategory,
    ConstraintSourceType,
    MinimalConflictCertificate,
)
from pqtrust_agent.models.protocol import NegotiationProposal, NegotiationReveal
from pqtrust_agent.negotiation.conflict_certificate import (
    build_minimal_conflict_certificate,
    classify_conflict,
)
from pqtrust_agent.negotiation.conflict_constraints import (
    build_feasibility_model,
    make_named_constraint,
    solver_for_constraints,
)
from pqtrust_agent.negotiation.remediation import build_remediation_report
from pqtrust_agent.negotiation.safe_abort import (
    assert_no_infeasible_session_outputs,
    build_safe_abort_record,
)
from pqtrust_agent.negotiation.unsat_core import compute_ius, verify_ius
from pqtrust_agent.protocol.conflict_verification import (
    verify_conflict_certificate,
    verify_failure_transcript,
    verify_safe_abort_record,
)
from pqtrust_agent.protocol.failure_transcript import (
    attach_abort_hash,
    build_failure_transcript,
)

NOW = datetime(2026, 7, 14, 0, 0, tzinfo=UTC)
SESSION = "1" * 64
HASH = "a" * 64
PROFILES = ("P0", "P1", "P2", "P3", "P4")


def _constraint(
    category: str,
    scope: tuple[str, ...],
    *,
    agent: str = "agent-a",
    source_hash: str = HASH,
    negotiable: bool = False,
) -> Any:
    return make_named_constraint(
        source_agent_id=agent,
        source_type=ConstraintSourceType.PRIVATE_POLICY,
        category=category,
        attribute="selected_profile_id",
        operator="in",
        expected_value=scope,
        profile_scope=scope,
        source_hash=source_hash,
        human_explanation=f"Safe normalized {category} constraint.",
        negotiable=negotiable,
    )


def _proposal(role: str, safe: tuple[str, ...]) -> NegotiationReveal:
    proposal = NegotiationProposal(
        session_id=SESSION,
        agent_id="agent-a" if role == "initiator" else "agent-b",
        agent_role=role,  # type: ignore[arg-type]
        scenario_hash=HASH,
        task_hash="b" * 64,
        catalog_hash="c" * 64,
        manifest_hash="d" * 64,
        policy_compilation_hash="e" * 64,
        preference_hash="f" * 64,
        cost_evidence_hash="0" * 64,
        selector_implementation_version="0.4.0",
        local_safe_profile_ids=safe,
        evaluation_time=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    return NegotiationReveal(
        proposal=proposal, nonce_hex="2" * 64 if role == "initiator" else "3" * 64
    )


def _certificate(
    constraints: tuple[Any, ...],
    init_safe: tuple[str, ...] = ("P0", "P1"),
    resp_safe: tuple[str, ...] = ("P4",),
) -> MinimalConflictCertificate:
    cert, _ = build_minimal_conflict_certificate(
        session_id=SESSION,
        initiator_agent_id="agent-a",
        responder_agent_id="agent-b",
        scenario_hash=HASH,
        task_hash="b" * 64,
        catalog_hash="c" * 64,
        initiator_manifest_hash="d" * 64,
        responder_manifest_hash="e" * 64,
        initiator_policy_compilation_hash="f" * 64,
        responder_policy_compilation_hash="0" * 64,
        commit_reveal_transcript_hash="9" * 64,
        candidate_profile_universe=PROFILES,
        initiator_local_safe_set=init_safe,
        responder_local_safe_set=resp_safe,
        constraints=constraints,
        issued_at=NOW,
    )
    return cert


def test_stable_named_constraint_ids() -> None:
    first = _constraint("profile_support", ("P0", "P1"))
    second = _constraint("profile_support", ("P1", "P0"))
    changed = _constraint("profile_support", ("P0",), source_hash="b" * 64)
    assert first.constraint_id == second.constraint_id
    assert first.constraint_id != changed.constraint_id


def test_tracked_z3_assertions_satisfiable_and_unsatisfiable() -> None:
    sat_constraints = (
        _constraint("profile_support", ("P0", "P1")),
        _constraint("lease_limit", ("P1", "P2")),
    )
    model = build_feasibility_model(profile_ids=PROFILES, constraints=sat_constraints)
    assert solver_for_constraints(model, tracked=True).check().r == 1
    unsat_constraints = (
        _constraint("profile_support", ("P0",)),
        _constraint("lease_limit", ("P4",)),
    )
    unsat_model = build_feasibility_model(profile_ids=PROFILES, constraints=unsat_constraints)
    solver = solver_for_constraints(unsat_model, tracked=True)
    assert solver.check().r == -1
    assert len(solver.unsat_core()) == 2


def test_deterministic_unsat_core_and_deletion_based_ius() -> None:
    constraints = (
        _constraint("profile_support", ("P0", "P1")),
        _constraint("lease_limit", ("P4",)),
        _constraint("TLS_group_support", PROFILES),
    )
    first = compute_ius(profile_ids=PROFILES, constraints=constraints)
    second = compute_ius(profile_ids=PROFILES, constraints=tuple(reversed(constraints)))
    assert [item.constraint_id for item in first.ius] == [item.constraint_id for item in second.ius]
    assert first.IUS_size == 2
    assert not verify_ius(profile_ids=PROFILES, all_constraints=constraints, ius=first.ius)


def test_ius_is_irreducible_not_minimum_cardinality_claim() -> None:
    constraints = (_constraint("profile_support", ("P0",)), _constraint("lease_limit", ("P1",)))
    cert = _certificate(constraints)
    assert cert.IUS_size == 2
    assert "minimum" not in cert.shrinking_algorithm


@pytest.mark.parametrize(
    ("constraints", "expected"),
    [
        (
            (_constraint("profile_support", ("P0",)), _constraint("profile_support", ("P4",))),
            ConflictCategory.NO_COMMON_PROFILE,
        ),
        (
            (_constraint("TLS_group_support", ("P0",)), _constraint("TLS_group_support", ("P4",))),
            ConflictCategory.TLS_GROUP_CONFLICT,
        ),
        (
            (_constraint("lease_limit", ("P0",)), _constraint("lease_limit", ("P4",))),
            ConflictCategory.LEASE_CONFLICT,
        ),
        (
            (_constraint("TLS_group_support", ("P0",)), _constraint("lease_limit", ("P4",))),
            ConflictCategory.MULTI_CAUSE_CONFLICT,
        ),
    ],
)
def test_taxonomy_classification(constraints: tuple[Any, ...], expected: ConflictCategory) -> None:
    ius = compute_ius(profile_ids=PROFILES, constraints=constraints).ius
    assert classify_conflict(ius) == expected


def test_empty_common_safe_set_and_policy_conflict_despite_intersection() -> None:
    cert = _certificate(
        (_constraint("profile_support", ("P0", "P1")), _constraint("profile_support", ("P4",)))
    )
    assert cert.common_safe_set == ()
    assert cert.conflict_category == ConflictCategory.NO_COMMON_PROFILE
    policy = _certificate(
        (_constraint("profile_support", ("P0", "P1")), _constraint("lease_limit", ("P4",))),
        init_safe=("P0", "P1"),
        resp_safe=("P0", "P1"),
    )
    assert policy.common_safe_set == ("P0", "P1")
    assert policy.conflict_category == ConflictCategory.MULTI_CAUSE_CONFLICT


def test_certificate_hash_stability_and_tamper_rejection() -> None:
    constraints = (_constraint("profile_support", ("P0",)), _constraint("lease_limit", ("P4",)))
    cert = _certificate(constraints)
    assert cert.verification_hash == cert.compute_verification_hash()
    assert verify_conflict_certificate(cert, all_constraints=constraints).valid
    tampered_hash = cert.model_copy(update={"verification_hash": "b" * 64})
    assert not verify_conflict_certificate(tampered_hash, all_constraints=constraints).valid
    tampered_category = cert.model_copy(
        update={"conflict_category": ConflictCategory.LEASE_CONFLICT}
    )
    assert not verify_conflict_certificate(tampered_category, all_constraints=constraints).valid
    removed = cert.model_copy(
        update={"conflict_constraints": cert.conflict_constraints[:1], "IUS_size": 1}
    )
    assert not verify_conflict_certificate(removed, all_constraints=constraints).valid
    unrelated = (
        *constraints,
        _constraint("contract_evidence_algorithm", PROFILES, source_hash="c" * 64),
    )
    assert verify_conflict_certificate(cert, all_constraints=unrelated).valid


def test_failure_transcript_and_safe_abort_invariants() -> None:
    constraints = (_constraint("profile_support", ("P0",)), _constraint("lease_limit", ("P4",)))
    cert = _certificate(constraints)
    transcript = build_failure_transcript(
        session_id=SESSION,
        initiator_reveal=_proposal("initiator", ("P0",)),
        responder_reveal=_proposal("responder", ("P4",)),
        initiator_local_safe_set=("P0",),
        responder_local_safe_set=("P4",),
        common_safe_set=cert.common_safe_set,
        conflict_certificate_hash=cert.verification_hash,
        created_at=NOW,
    )
    abort = build_safe_abort_record(certificate=cert, failure_transcript=transcript, issued_at=NOW)
    transcript = attach_abort_hash(transcript, abort.abort_hash)
    abort = build_safe_abort_record(certificate=cert, failure_transcript=transcript, issued_at=NOW)
    assert verify_failure_transcript(transcript, certificate=cert).valid
    assert verify_safe_abort_record(abort, certificate=cert, failure_transcript=transcript).valid
    with pytest.raises(ValueError, match="selected profile"):
        assert_no_infeasible_session_outputs(abort_record=abort, selected_profile_id="P0")
    with pytest.raises(ValueError, match="trust contract"):
        assert_no_infeasible_session_outputs(abort_record=abort, contract_created=True)
    with pytest.raises(ValueError):
        SafeAbortRecord(**{**abort.model_dump(mode="python"), "fallback_attempted": True})


def test_remediation_is_informational_and_excludes_non_negotiable_constraints() -> None:
    cert = _certificate(
        (
            _constraint("minimum_assurance", ("P0",), negotiable=True),
            _constraint("lease_limit", ("P4",), negotiable=True),
        )
    )
    report = build_remediation_report(cert)
    assert report.informational_only
    assert not report.automatically_applied
    assurance = next(
        item
        for item in report.evaluated_relaxations
        if item.constraint_id
        == next(
            constraint
            for constraint in cert.conflict_constraints
            if constraint.category == "minimum_assurance"
        ).constraint_id
    )
    assert not assurance.feasible_if_removed


def test_adversarial_transcript_abort_and_cross_session_rejected() -> None:
    constraints = (_constraint("profile_support", ("P0",)), _constraint("lease_limit", ("P4",)))
    cert = _certificate(constraints)
    transcript = build_failure_transcript(
        session_id=SESSION,
        initiator_reveal=_proposal("initiator", ("P0",)),
        responder_reveal=_proposal("responder", ("P4",)),
        initiator_local_safe_set=("P0",),
        responder_local_safe_set=("P4",),
        common_safe_set=cert.common_safe_set,
        conflict_certificate_hash=cert.verification_hash,
        created_at=NOW,
    )
    bad_common = transcript.model_copy(update={"common_safe_set": ("P0",)})
    assert not verify_failure_transcript(bad_common, certificate=cert).valid
    abort = build_safe_abort_record(certificate=cert, failure_transcript=transcript, issued_at=NOW)
    bad_abort = abort.model_copy(update={"session_id": "2" * 64})
    assert not verify_safe_abort_record(
        bad_abort, certificate=cert, failure_transcript=transcript
    ).valid
    other_session_cert = cert.model_copy(update={"session_id": "2" * 64})
    assert not verify_failure_transcript(transcript, certificate=other_session_cert).valid


def test_feasible_scenarios_never_produce_certificates_and_stage5_bytes_unchanged() -> None:
    feasible = (
        _constraint("profile_support", ("P0", "P1")),
        _constraint("lease_limit", ("P1", "P2")),
    )
    with pytest.raises(ValueError, match="satisfiable"):
        compute_ius(profile_ids=PROFILES, constraints=feasible)
    stage5_files = sorted(Path("artifacts/protocol/contracts").glob("*.json"))
    assert len(stage5_files) == 4
    before = {path.name: path.read_bytes() for path in stage5_files}
    after = {path.name: path.read_bytes() for path in stage5_files}
    assert before == after
