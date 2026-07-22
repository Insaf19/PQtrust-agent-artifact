"""Safe fail-closed abort construction and invariants."""

from __future__ import annotations

from datetime import datetime

from pqtrust_agent.models.abort import SafeAbortRecord, abort_id_for
from pqtrust_agent.models.conflict import MinimalConflictCertificate
from pqtrust_agent.protocol.failure_transcript import NegotiationFailureTranscript


def build_safe_abort_record(
    *,
    certificate: MinimalConflictCertificate,
    failure_transcript: NegotiationFailureTranscript,
    issued_at: datetime,
) -> SafeAbortRecord:
    abort = SafeAbortRecord(
        abort_id=abort_id_for(certificate.session_id, certificate.verification_hash),
        session_id=certificate.session_id,
        scenario_hash=certificate.scenario_hash,
        conflict_certificate_hash=certificate.verification_hash,
        failure_transcript_hash=failure_transcript.transcript_hash,
        abort_reason_code=certificate.conflict_category.value,
        issued_at=issued_at,
        abort_hash="0" * 64,
    )
    return abort.model_copy(update={"abort_hash": abort.compute_abort_hash()})


def assert_no_infeasible_session_outputs(
    *,
    abort_record: SafeAbortRecord,
    selected_profile_id: str | None = None,
    contract_created: bool = False,
    fallback_attempted: bool = False,
) -> None:
    if abort_record.selected_profile_id is not None or selected_profile_id is not None:
        raise ValueError("infeasible session cannot attach a selected profile")
    if abort_record.contract_created or contract_created:
        raise ValueError("infeasible session cannot attach a trust contract")
    if abort_record.fallback_attempted or fallback_attempted:
        raise ValueError("infeasible session cannot attempt fallback")
