"""Independent Stage 6 conflict, failure-transcript, and abort verification."""

from __future__ import annotations

import z3
from pydantic import BaseModel, ConfigDict

from pqtrust_agent.models.abort import SafeAbortRecord, abort_id_for
from pqtrust_agent.models.conflict import MinimalConflictCertificate, certificate_id_for
from pqtrust_agent.models.protocol import raw_commitment_hash
from pqtrust_agent.negotiation.conflict_certificate import classify_conflict
from pqtrust_agent.negotiation.conflict_constraints import (
    build_feasibility_model,
    solver_for_constraints,
)
from pqtrust_agent.negotiation.unsat_core import verify_ius
from pqtrust_agent.protocol.failure_transcript import NegotiationFailureTranscript


class ValidationErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    message: str


class ConflictValidationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    errors: tuple[ValidationErrorDetail, ...]


def verify_conflict_certificate(
    certificate: MinimalConflictCertificate,
    *,
    all_constraints: tuple[object, ...] | None = None,
) -> ConflictValidationResult:
    errors: list[ValidationErrorDetail] = []
    constraints = certificate.conflict_constraints
    model_constraints = (
        constraints
        if all_constraints is None
        else tuple(
            item
            for item in all_constraints
            if hasattr(item, "constraint_id") and hasattr(item, "profile_scope")
        )
    )
    full_model = build_feasibility_model(
        profile_ids=certificate.candidate_profile_universe,
        constraints=model_constraints,  # type: ignore[arg-type]
    )
    if solver_for_constraints(full_model, tracked=False).check() != z3.unsat:
        errors.append(_err("MODEL_NOT_UNSAT", "rebuilt complete feasibility model is satisfiable"))
    for message in verify_ius(
        profile_ids=certificate.candidate_profile_universe,
        all_constraints=model_constraints,  # type: ignore[arg-type]
        ius=constraints,
    ):
        errors.append(_err("IUS_INVALID", message))
    expected_category = classify_conflict(constraints)
    if certificate.conflict_category != expected_category:
        errors.append(_err("CATEGORY_MISMATCH", "conflict category does not match final IUS"))
    expected_id = certificate_id_for(
        certificate.session_id,
        tuple(constraint.constraint_id for constraint in constraints),
    )
    if certificate.certificate_id != expected_id:
        errors.append(_err("CERTIFICATE_ID_MISMATCH", "certificate ID does not match IUS"))
    if certificate.verification_hash != certificate.compute_verification_hash():
        errors.append(_err("CERTIFICATE_HASH_MISMATCH", "certificate verification hash mismatch"))
    return ConflictValidationResult(valid=not errors, errors=tuple(errors))


def verify_failure_transcript(
    transcript: NegotiationFailureTranscript,
    *,
    certificate: MinimalConflictCertificate,
) -> ConflictValidationResult:
    errors: list[ValidationErrorDetail] = []
    initiator_commitment = raw_commitment_hash(
        transcript.initiator_reveal.proposal.canonical_bytes(),
        transcript.initiator_reveal.nonce_bytes(),
    )
    responder_commitment = raw_commitment_hash(
        transcript.responder_reveal.proposal.canonical_bytes(),
        transcript.responder_reveal.nonce_bytes(),
    )
    if transcript.initiator_commitment != initiator_commitment:
        errors.append(_err("COMMITMENT_MISMATCH", "initiator commitment does not recompute"))
    if transcript.responder_commitment != responder_commitment:
        errors.append(_err("COMMITMENT_MISMATCH", "responder commitment does not recompute"))
    if transcript.initiator_proposal_hash != transcript.initiator_reveal.proposal.proposal_hash():
        errors.append(_err("PROPOSAL_HASH_MISMATCH", "initiator proposal hash mismatch"))
    if transcript.responder_proposal_hash != transcript.responder_reveal.proposal.proposal_hash():
        errors.append(_err("PROPOSAL_HASH_MISMATCH", "responder proposal hash mismatch"))
    if transcript.conflict_certificate_hash != certificate.verification_hash:
        errors.append(
            _err("CERTIFICATE_HASH_MISMATCH", "failure transcript certificate hash mismatch")
        )
    if transcript.session_id != certificate.session_id:
        errors.append(
            _err("SESSION_MISMATCH", "failure transcript session differs from certificate")
        )
    if transcript.common_safe_set != certificate.common_safe_set:
        errors.append(_err("COMMON_SAFE_SET_MISMATCH", "common safe set was not recomputed"))
    if transcript.transcript_hash != transcript.compute_transcript_hash():
        errors.append(_err("TRANSCRIPT_HASH_MISMATCH", "failure transcript hash mismatch"))
    return ConflictValidationResult(valid=not errors, errors=tuple(errors))


def verify_safe_abort_record(
    abort_record: SafeAbortRecord,
    *,
    certificate: MinimalConflictCertificate,
    failure_transcript: NegotiationFailureTranscript,
) -> ConflictValidationResult:
    errors: list[ValidationErrorDetail] = []
    abort_payload = abort_record.model_dump(mode="python")
    if abort_payload["selected_profile_id"] is not None:
        errors.append(_err("SELECTED_PROFILE_AFTER_ABORT", "abort record selected a profile"))
    if abort_payload["contract_created"]:
        errors.append(_err("CONTRACT_AFTER_ABORT", "abort record created a contract"))
    if abort_payload["fallback_attempted"]:
        errors.append(_err("FALLBACK_AFTER_ABORT", "abort record attempted fallback"))
    if abort_record.session_id != certificate.session_id:
        errors.append(_err("SESSION_MISMATCH", "abort record session differs from certificate"))
    if abort_record.conflict_certificate_hash != certificate.verification_hash:
        errors.append(_err("CERTIFICATE_HASH_MISMATCH", "abort record certificate hash mismatch"))
    if abort_record.failure_transcript_hash != failure_transcript.transcript_hash:
        errors.append(_err("TRANSCRIPT_HASH_MISMATCH", "abort record transcript hash mismatch"))
    if abort_record.abort_id != abort_id_for(certificate.session_id, certificate.verification_hash):
        errors.append(_err("ABORT_ID_MISMATCH", "abort ID mismatch"))
    if abort_record.abort_hash != abort_record.compute_abort_hash():
        errors.append(_err("ABORT_HASH_MISMATCH", "abort hash mismatch"))
    return ConflictValidationResult(valid=not errors, errors=tuple(errors))


def _err(code: str, message: str) -> ValidationErrorDetail:
    return ValidationErrorDetail(code=code, message=message)
