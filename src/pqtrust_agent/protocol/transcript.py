"""Transcript construction and verification."""

from __future__ import annotations

from datetime import datetime

from pqtrust_agent.models.protocol import NegotiationReveal, NegotiationTranscript
from pqtrust_agent.models.selection import BilateralSelectionResult
from pqtrust_agent.negotiation.selector import common_safe_set
from pqtrust_agent.protocol.commitment import create_commitment
from pqtrust_agent.protocol.replay import ReplayRegistry
from pqtrust_agent.protocol.time import require_proposal_active, require_utc_aware


def build_transcript(
    *,
    initiator_reveal: NegotiationReveal,
    responder_reveal: NegotiationReveal,
    selection_result: BilateralSelectionResult,
    catalog_profile_ids: tuple[str, ...],
    created_at: datetime,
) -> NegotiationTranscript:
    """Build a transcript from reveals and an already recomputed selector result."""

    created = require_utc_aware(created_at, phase="transcript_creation")
    initiator_safe = initiator_reveal.proposal.local_safe_profile_ids
    responder_safe = responder_reveal.proposal.local_safe_profile_ids
    common = common_safe_set(catalog_profile_ids, initiator_safe, responder_safe)
    if common != selection_result.common_safe_set:
        raise ValueError("selection common-safe set does not match revealed proposals")
    transcript = NegotiationTranscript(
        session_id=initiator_reveal.proposal.session_id,
        initiator_commitment=create_commitment(initiator_reveal),
        responder_commitment=create_commitment(responder_reveal),
        initiator_reveal=initiator_reveal,
        responder_reveal=responder_reveal,
        initiator_local_safe_set=initiator_safe,
        responder_local_safe_set=responder_safe,
        common_safe_set=selection_result.common_safe_set,
        Pareto_frontier=selection_result.pareto_frontier,
        selected_profile_id=selection_result.selected_profile_id,
        selection_hash=selection_result.selection_hash,
        transcript_created_at=created,
        transcript_hash="0" * 64,
    )
    return transcript.model_copy(update={"transcript_hash": transcript.compute_transcript_hash()})


def verify_transcript(
    transcript: NegotiationTranscript,
    *,
    selection_result: BilateralSelectionResult,
    catalog_profile_ids: tuple[str, ...],
    verification_time: datetime,
    replay_registry: ReplayRegistry | None = None,
) -> None:
    """Fail closed unless the transcript matches commitments and recomputed selection."""

    if transcript.initiator_commitment != create_commitment(transcript.initiator_reveal):
        raise ValueError("initiator commitment mismatch")
    if transcript.responder_commitment != create_commitment(transcript.responder_reveal):
        raise ValueError("responder commitment mismatch")
    initiator = transcript.initiator_reveal.proposal
    responder = transcript.responder_reveal.proposal
    for proposal in (initiator, responder):
        require_proposal_active(
            evaluation_time=proposal.evaluation_time,
            expires_at=proposal.expires_at,
            verification_time=verification_time,
            phase="transcript_validation",
        )
    if (
        initiator.proposal_hash() == responder.proposal_hash()
        and initiator.agent_id != responder.agent_id
    ):
        raise ValueError("proposal hash collision across distinct proposals")
    if (
        initiator.session_id != responder.session_id
        or initiator.session_id != transcript.session_id
    ):
        raise ValueError("session mismatch")
    if initiator.agent_role != "initiator" or responder.agent_role != "responder":
        raise ValueError("proposal roles mismatch")
    for field in ("scenario_hash", "task_hash", "catalog_hash", "cost_evidence_hash"):
        if getattr(initiator, field) != getattr(responder, field):
            raise ValueError(f"{field} mismatch")
    common = common_safe_set(
        catalog_profile_ids,
        initiator.local_safe_profile_ids,
        responder.local_safe_profile_ids,
    )
    if common != transcript.common_safe_set:
        raise ValueError("common-safe set mismatch")
    if transcript.initiator_local_safe_set != initiator.local_safe_profile_ids:
        raise ValueError("initiator local safe set mismatch")
    if transcript.responder_local_safe_set != responder.local_safe_profile_ids:
        raise ValueError("responder local safe set mismatch")
    if transcript.common_safe_set != selection_result.common_safe_set:
        raise ValueError("selection common-safe set mismatch")
    if transcript.Pareto_frontier != selection_result.pareto_frontier:
        raise ValueError("Pareto frontier mismatch")
    if transcript.selected_profile_id != selection_result.selected_profile_id:
        raise ValueError("selected profile mismatch")
    if transcript.selection_hash != selection_result.selection_hash:
        raise ValueError("selection hash mismatch")
    if transcript.transcript_hash != transcript.compute_transcript_hash():
        raise ValueError("transcript hash mismatch")
    if replay_registry is not None:
        replay_registry.register_transcript(
            transcript.session_id,
            transcript.transcript_hash,
            reference_time=verification_time,
        )
