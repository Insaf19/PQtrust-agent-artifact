"""Unsigned and signed trust contract construction."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from pqtrust_agent.models.catalog import ProfileCatalog
from pqtrust_agent.models.contract import (
    AgentContractSignature,
    SignedTrustContract,
    UnsignedTrustContract,
)
from pqtrust_agent.models.protocol import NegotiationTranscript
from pqtrust_agent.models.selection import BilateralSelectionResult
from pqtrust_agent.protocol.time import require_utc_aware


def contract_id_for_transcript(transcript_hash: str) -> str:
    return hashlib.sha256(b"PQTrust.ContractID.v1\x00" + bytes.fromhex(transcript_hash)).hexdigest()


def build_unsigned_contract(
    *,
    transcript: NegotiationTranscript,
    selection_result: BilateralSelectionResult,
    catalog: ProfileCatalog,
    issued_at: datetime,
    lease_seconds: int | None = None,
) -> UnsignedTrustContract:
    """Build an unsigned contract with selected profile properties copied from catalog."""

    profile = catalog.get_profile(selection_result.selected_profile_id)
    issued = require_utc_aware(issued_at, phase="contract_construction")
    duration = lease_seconds if lease_seconds is not None else profile.max_lease_seconds
    if duration <= 0 or duration > profile.max_lease_seconds:
        raise ValueError("contract lease exceeds selected profile maximum")
    initiator = transcript.initiator_reveal.proposal
    responder = transcript.responder_reveal.proposal
    return UnsignedTrustContract(
        contract_id=contract_id_for_transcript(transcript.transcript_hash),
        session_id=transcript.session_id,
        initiator_agent_id=initiator.agent_id,
        responder_agent_id=responder.agent_id,
        scenario_hash=initiator.scenario_hash,
        task_hash=initiator.task_hash,
        catalog_hash=initiator.catalog_hash,
        cost_evidence_hash=initiator.cost_evidence_hash,
        initiator_manifest_hash=initiator.manifest_hash,
        responder_manifest_hash=responder.manifest_hash,
        initiator_policy_compilation_hash=initiator.policy_compilation_hash,
        responder_policy_compilation_hash=responder.policy_compilation_hash,
        initiator_preference_hash=initiator.preference_hash,
        responder_preference_hash=responder.preference_hash,
        transcript_hash=transcript.transcript_hash,
        selection_hash=selection_result.selection_hash,
        common_safe_profile_ids=selection_result.common_safe_set,
        Pareto_frontier_profile_ids=selection_result.pareto_frontier,
        selected_profile_id=selection_result.selected_profile_id,
        tls_group=profile.tls_group,
        endpoint_authentication_mode=profile.endpoint_authentication_mode,
        contract_evidence_mode=profile.contract_evidence_mode,
        fallback_rule=profile.fallback_rule,
        resumption_rule=profile.resumption_rule,
        lease_strictness=profile.lease_strictness,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=duration),
    )


def build_signed_contract(
    *,
    unsigned_contract: UnsignedTrustContract,
    initiator_signature: AgentContractSignature,
    responder_signature: AgentContractSignature,
) -> SignedTrustContract:
    signed = SignedTrustContract(
        unsigned_contract=unsigned_contract,
        initiator_signature=initiator_signature,
        responder_signature=responder_signature,
        signed_contract_hash="0" * 64,
    )
    return signed.model_copy(update={"signed_contract_hash": signed.compute_signed_contract_hash()})
