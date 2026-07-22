"""Commit-reveal helpers and phase enforcement."""

from __future__ import annotations

import secrets
from datetime import datetime

from pqtrust_agent.models.protocol import NegotiationReveal, raw_commitment_hash
from pqtrust_agent.protocol.replay import ReplayRegistry
from pqtrust_agent.protocol.time import require_proposal_active


def production_nonce_hex() -> str:
    """Return a production nonce from OS randomness."""

    return secrets.token_bytes(32).hex()


def create_commitment(reveal: NegotiationReveal) -> str:
    """Return the Stage 5 commitment hash for a reveal."""

    return raw_commitment_hash(reveal.proposal.canonical_bytes(), reveal.nonce_bytes())


def verify_commitment(commitment: str, reveal: NegotiationReveal) -> bool:
    """Return true when a reveal matches an earlier commitment."""

    return create_commitment(reveal) == commitment


def reveal_hash(reveal: NegotiationReveal) -> str:
    return reveal.reveal_hash()


class CommitRevealSession:
    """Local session state enforcing commitment-before-reveal ordering."""

    def __init__(
        self,
        *,
        session_id: str,
        activation_time: datetime,
        replay_registry: ReplayRegistry | None = None,
    ) -> None:
        self.session_id = session_id
        self._replay_registry = replay_registry
        self._activation_time = activation_time
        self._commitments: dict[str, str] = {}
        self._reveals: dict[str, NegotiationReveal] = {}
        if replay_registry is not None:
            replay_registry.register_session(session_id, reference_time=activation_time)

    @property
    def commitments(self) -> dict[str, str]:
        return dict(self._commitments)

    @property
    def reveals(self) -> dict[str, NegotiationReveal]:
        return dict(self._reveals)

    def register_commitment(self, role: str, commitment: str) -> None:
        if role not in {"initiator", "responder"}:
            raise ValueError("role must be initiator or responder")
        if role in self._commitments:
            raise ValueError(f"{role} commitment already registered")
        if self._replay_registry is not None:
            self._replay_registry.register_commitment(
                self.session_id,
                commitment,
                reference_time=self._activation_time,
            )
        self._commitments[role] = commitment

    def accept_reveal(self, reveal: NegotiationReveal, *, verification_time: datetime) -> None:
        role = reveal.proposal.agent_role
        if set(self._commitments) != {"initiator", "responder"}:
            raise ValueError("both commitments must be registered before reveal")
        if role in self._reveals:
            raise ValueError(f"{role} reveal already accepted")
        if reveal.proposal.session_id != self.session_id:
            raise ValueError("reveal session_id mismatch")
        if not verify_commitment(self._commitments[role], reveal):
            raise ValueError("reveal does not match commitment")
        require_proposal_active(
            evaluation_time=reveal.proposal.evaluation_time,
            expires_at=reveal.proposal.expires_at,
            verification_time=verification_time,
            phase="reveal_acceptance",
        )
        self._reveals[role] = reveal
        if set(self._reveals) == {"initiator", "responder"}:
            self._validate_pair()

    def _validate_pair(self) -> None:
        initiator = self._reveals["initiator"].proposal
        responder = self._reveals["responder"].proposal
        if initiator.agent_role == responder.agent_role:
            raise ValueError("roles must be distinct")
        if initiator.agent_id == responder.agent_id:
            raise ValueError("agent IDs must be distinct")
        fields = ("session_id", "scenario_hash", "task_hash", "catalog_hash", "cost_evidence_hash")
        for field in fields:
            if getattr(initiator, field) != getattr(responder, field):
                raise ValueError(f"{field} mismatch")
