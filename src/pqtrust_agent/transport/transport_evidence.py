"""Transport execution evidence verification."""

from __future__ import annotations

from pqtrust_agent.models.runtime import RuntimeState
from pqtrust_agent.models.transport import TransportExecutionEvidence
from pqtrust_agent.runtime.state_machine import ALLOWED_TRANSITIONS
from pqtrust_agent.tls_groups import require_matching_tls_groups


def verify_transport_evidence(evidence: TransportExecutionEvidence) -> None:
    if evidence.transport_evidence_hash != evidence.compute_transport_evidence_hash():
        raise ValueError("transport evidence hash mismatch")
    require_matching_tls_groups(
        requested=evidence.requested_tls_group,
        negotiated=evidence.negotiated_tls_group,
    )
    if evidence.tls_version != "TLSv1.3":
        raise ValueError("unexpected TLS version")
    if evidence.fallback_attempted:
        raise ValueError("fallback occurred")
    states = [RuntimeState.CREATED]
    for transition in evidence.state_transition_trace:
        _, _, to_state = transition.partition("->")
        if not to_state:
            raise ValueError("invalid state transition trace entry")
        next_state = RuntimeState(to_state)
        if next_state not in ALLOWED_TRANSITIONS[states[-1]]:
            raise ValueError("illegal state transition trace")
        states.append(next_state)
