"""Protocol transcript and signed contract verification."""

from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path

from pqtrust_agent.crypto.agent_evidence_manifest import KeyLocator
from pqtrust_agent.crypto.contract_signer import OpenSSLContractSigner
from pqtrust_agent.models.catalog import ProfileCatalog
from pqtrust_agent.models.common import EvidenceAlgorithm
from pqtrust_agent.models.contract import AgentContractSignature, SignedTrustContract
from pqtrust_agent.models.protocol import NegotiationTranscript
from pqtrust_agent.models.selection import BilateralSelectionResult
from pqtrust_agent.protocol.replay import ReplayRegistry
from pqtrust_agent.protocol.signature import algorithm_for_contract_evidence
from pqtrust_agent.protocol.time import require_contract_active
from pqtrust_agent.protocol.transcript import verify_transcript


def verify_signed_contract(
    signed_contract: SignedTrustContract,
    *,
    transcript: NegotiationTranscript,
    selection_result: BilateralSelectionResult,
    catalog: ProfileCatalog,
    expected_keys: dict[KeyLocator, tuple[str, str, Path]],
    verification_time: datetime,
    signer: OpenSSLContractSigner | None = None,
    replay_registry: ReplayRegistry | None = None,
) -> None:
    """Verify the signed contract and fail closed on any mismatch."""

    verify_transcript(
        transcript,
        selection_result=selection_result,
        catalog_profile_ids=catalog.profile_ids(),
        verification_time=verification_time,
    )
    unsigned = signed_contract.unsigned_contract
    if signed_contract.signed_contract_hash != signed_contract.compute_signed_contract_hash():
        raise ValueError("signed contract hash mismatch")
    if unsigned.transcript_hash != transcript.transcript_hash:
        raise ValueError("contract transcript hash mismatch")
    if unsigned.selection_hash != selection_result.selection_hash:
        raise ValueError("contract selection hash mismatch")
    if unsigned.selected_profile_id != selection_result.selected_profile_id:
        raise ValueError("contract selected profile mismatch")
    if unsigned.selected_profile_id not in transcript.initiator_local_safe_set:
        raise ValueError("selected profile not in initiator safe set")
    if unsigned.selected_profile_id not in transcript.responder_local_safe_set:
        raise ValueError("selected profile not in responder safe set")
    profile = catalog.get_profile(unsigned.selected_profile_id)
    if unsigned.tls_group != profile.tls_group:
        raise ValueError("TLS group modified")
    if unsigned.endpoint_authentication_mode != profile.endpoint_authentication_mode:
        raise ValueError("endpoint authentication mode mismatch")
    if unsigned.contract_evidence_mode != profile.contract_evidence_mode:
        raise ValueError("contract evidence mode mismatch")
    if unsigned.expires_at <= unsigned.issued_at:
        raise ValueError("invalid contract lease interval")
    require_contract_active(
        issued_at=unsigned.issued_at,
        expires_at=unsigned.expires_at,
        activation_time=verification_time,
        phase="contract_verification",
    )
    if (unsigned.expires_at - unsigned.issued_at).total_seconds() > profile.max_lease_seconds:
        raise ValueError("contract lease exceeds selected profile maximum")
    required_algorithm = algorithm_for_contract_evidence(profile.contract_evidence_mode)
    backend = signer or OpenSSLContractSigner()
    _verify_one(
        signed_contract.initiator_signature,
        expected_agent=unsigned.initiator_agent_id,
        expected_role="initiator",
        required_algorithm=required_algorithm,
        expected_keys=expected_keys,
        payload=unsigned.canonical_bytes(),
        backend=backend,
    )
    _verify_one(
        signed_contract.responder_signature,
        expected_agent=unsigned.responder_agent_id,
        expected_role="responder",
        required_algorithm=required_algorithm,
        expected_keys=expected_keys,
        payload=unsigned.canonical_bytes(),
        backend=backend,
    )
    if replay_registry is not None:
        replay_registry.register_contract(
            contract_id=unsigned.contract_id,
            contract_hash=signed_contract.signed_contract_hash,
            session_id=unsigned.session_id,
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
            activation_time=verification_time,
        )


def _verify_one(
    signature: AgentContractSignature,
    *,
    expected_agent: str,
    expected_role: str,
    required_algorithm: EvidenceAlgorithm,
    expected_keys: dict[KeyLocator, tuple[str, str, Path]],
    payload: bytes,
    backend: OpenSSLContractSigner,
) -> None:
    if signature.agent_id != expected_agent:
        raise ValueError("wrong signing agent")
    if signature.role != expected_role:
        raise ValueError("wrong signing role")
    if signature.algorithm != required_algorithm:
        raise ValueError("wrong ML-DSA parameter set")
    expected = expected_keys.get(KeyLocator(signature.agent_id, signature.algorithm))
    if expected is None:
        raise ValueError("missing expected key")
    expected_key_id, expected_public_hash, public_key_path = expected
    if signature.key_id != expected_key_id:
        raise ValueError("wrong key ID")
    if signature.public_key_sha256 != expected_public_hash:
        raise ValueError("wrong public key fingerprint")
    try:
        signature_bytes = base64.b64decode(signature.signature_base64, validate=True)
    except Exception as exc:
        raise ValueError("invalid signature encoding") from exc
    if not signature_bytes:
        raise ValueError("missing signature")
    if not backend.verify_bytes(payload, signature_bytes, public_key_path):
        raise ValueError("invalid signature")
