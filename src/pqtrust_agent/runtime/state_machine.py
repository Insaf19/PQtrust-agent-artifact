"""Deterministic Stage 7 runtime state machine."""

from __future__ import annotations

from pqtrust_agent.models.runtime import RuntimeState, StateTransitionRecord
from pqtrust_agent.runtime.errors import RuntimeStateError

ALLOWED_TRANSITIONS: dict[RuntimeState, frozenset[RuntimeState]] = {
    RuntimeState.CREATED: frozenset({RuntimeState.DISCOVERY_COMPLETE, RuntimeState.FAILED}),
    RuntimeState.DISCOVERY_COMPLETE: frozenset(
        {RuntimeState.COMMITMENTS_REGISTERED, RuntimeState.FAILED}
    ),
    RuntimeState.COMMITMENTS_REGISTERED: frozenset(
        {RuntimeState.REVEALS_VERIFIED, RuntimeState.FAILED}
    ),
    RuntimeState.REVEALS_VERIFIED: frozenset(
        {RuntimeState.FEASIBILITY_EVALUATED, RuntimeState.FAILED}
    ),
    RuntimeState.FEASIBILITY_EVALUATED: frozenset(
        {RuntimeState.PROFILE_SELECTED, RuntimeState.CONFLICT_CERTIFIED, RuntimeState.FAILED}
    ),
    RuntimeState.PROFILE_SELECTED: frozenset({RuntimeState.CONTRACT_CREATED, RuntimeState.FAILED}),
    RuntimeState.CONTRACT_CREATED: frozenset({RuntimeState.CONTRACT_VERIFIED, RuntimeState.FAILED}),
    RuntimeState.CONTRACT_VERIFIED: frozenset({RuntimeState.TLS_ACTIVATED, RuntimeState.FAILED}),
    RuntimeState.TLS_ACTIVATED: frozenset({RuntimeState.TASK_EXECUTED, RuntimeState.FAILED}),
    RuntimeState.TASK_EXECUTED: frozenset({RuntimeState.COMPLETED, RuntimeState.FAILED}),
    RuntimeState.CONFLICT_CERTIFIED: frozenset({RuntimeState.ABORTED, RuntimeState.FAILED}),
    RuntimeState.COMPLETED: frozenset(),
    RuntimeState.ABORTED: frozenset(),
    RuntimeState.FAILED: frozenset(),
}


class RuntimeStateMachine:
    """Minimal deterministic transition recorder."""

    def __init__(self) -> None:
        self._state = RuntimeState.CREATED
        self._trace: list[StateTransitionRecord] = []

    @property
    def state(self) -> RuntimeState:
        return self._state

    @property
    def trace(self) -> tuple[StateTransitionRecord, ...]:
        return tuple(self._trace)

    def transition(self, to_state: RuntimeState, *, reason: str) -> None:
        allowed = ALLOWED_TRANSITIONS[self._state]
        if to_state not in allowed:
            raise RuntimeStateError(f"illegal transition {self._state.value}->{to_state.value}")
        self._trace.append(
            StateTransitionRecord(from_state=self._state, to_state=to_state, reason=reason)
        )
        self._state = to_state
