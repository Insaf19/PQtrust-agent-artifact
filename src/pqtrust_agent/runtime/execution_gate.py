"""Contract-enforced Stage 7 execution gate."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pqtrust_agent.crypto.agent_evidence_manifest import KeyLocator
from pqtrust_agent.crypto.contract_signer import OpenSSLContractSigner
from pqtrust_agent.models.catalog import ProfileCatalog
from pqtrust_agent.models.contract import SignedTrustContract
from pqtrust_agent.models.protocol import NegotiationTranscript
from pqtrust_agent.models.runtime import RuntimeState
from pqtrust_agent.models.selection import BilateralSelectionResult
from pqtrust_agent.models.transport import AuthorizedExecutionContext, ExecutionGateRejection
from pqtrust_agent.protocol.replay import ReplayRegistry
from pqtrust_agent.protocol.verification import verify_signed_contract

GateResult = AuthorizedExecutionContext | ExecutionGateRejection
Verifier = Callable[
    [
        SignedTrustContract,
        NegotiationTranscript,
        BilateralSelectionResult,
        ProfileCatalog,
        datetime,
    ],
    None,
]


class ExecutionGate:
    """Fail-closed authorization gate before any TLS activation."""

    def __init__(
        self,
        *,
        catalog: ProfileCatalog,
        expected_keys: dict[KeyLocator, tuple[str, str, Path]] | None = None,
        replay_registry: ReplayRegistry | None = None,
        signer: OpenSSLContractSigner | None = None,
        verifier: Verifier | None = None,
    ) -> None:
        self.catalog = catalog
        self.expected_keys = expected_keys or {}
        self.replay_registry = replay_registry
        self.signer = signer
        self.verifier = verifier

    def authorize(
        self,
        *,
        session_id: str,
        signed_contract: SignedTrustContract,
        transcript: NegotiationTranscript,
        selection_result: BilateralSelectionResult,
        activation_time: datetime,
        runtime_state: RuntimeState,
    ) -> GateResult:
        try:
            if runtime_state != RuntimeState.CONTRACT_VERIFIED:
                raise ValueError("runtime is not in CONTRACT_VERIFIED state")
            unsigned = signed_contract.unsigned_contract
            if unsigned.session_id != session_id or transcript.session_id != session_id:
                raise ValueError("session IDs do not match")
            computed_contract_hash = signed_contract.compute_signed_contract_hash()
            if signed_contract.signed_contract_hash != computed_contract_hash:
                raise ValueError("modified signed-contract hash")
            if self.verifier is not None:
                self.verifier(
                    signed_contract,
                    transcript,
                    selection_result,
                    self.catalog,
                    activation_time,
                )
            else:
                verify_signed_contract(
                    signed_contract,
                    transcript=transcript,
                    selection_result=selection_result,
                    catalog=self.catalog,
                    expected_keys=self.expected_keys,
                    verification_time=activation_time,
                    signer=self.signer,
                    replay_registry=self.replay_registry,
                )
            profile = self.catalog.get_profile(unsigned.selected_profile_id)
            if unsigned.selected_profile_id not in transcript.initiator_local_safe_set:
                raise ValueError("selected profile not in initiator safe set")
            if unsigned.selected_profile_id not in transcript.responder_local_safe_set:
                raise ValueError("selected profile not in responder safe set")
            if unsigned.tls_group != profile.tls_group:
                raise ValueError("profile properties do not match catalog")
            if unsigned.transcript_hash != transcript.transcript_hash:
                raise ValueError("transcript hash mismatch")
            if unsigned.selection_hash != selection_result.selection_hash:
                raise ValueError("selection hash mismatch")
            return AuthorizedExecutionContext(
                session_id=session_id,
                selected_profile_id=unsigned.selected_profile_id,
                tls_group=unsigned.tls_group,
                endpoint_authentication_mode=unsigned.endpoint_authentication_mode,
                contract_evidence_mode=unsigned.contract_evidence_mode,
                fallback_rule=unsigned.fallback_rule,
                resumption_rule=unsigned.resumption_rule,
                activation_time=activation_time,
                contract_hash=signed_contract.signed_contract_hash,
            )
        except Exception as exc:
            return ExecutionGateRejection(error_code=type(exc).__name__, message=str(exc))
