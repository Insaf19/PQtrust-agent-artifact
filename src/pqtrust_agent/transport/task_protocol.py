"""Contract-bound deterministic task protocol."""

from __future__ import annotations

import hashlib

from pqtrust_agent.models.runtime import RuntimeState
from pqtrust_agent.models.task_execution import TaskRequest, TaskResponse
from pqtrust_agent.models.transport import AuthorizedExecutionContext
from pqtrust_agent.runtime.errors import TaskProtocolError


class TaskProtocol:
    def __init__(self) -> None:
        self._requests: set[str] = set()
        self._responses: set[str] = set()

    def build_request(
        self,
        *,
        context: AuthorizedExecutionContext,
        scenario_hash: str,
        payload: bytes,
        request_sequence_number: int,
    ) -> TaskRequest:
        return TaskRequest(
            task_id=hashlib.sha256(b"PQTrust.Stage7.Task.v1\x00" + payload).hexdigest(),
            session_id=context.session_id,
            contract_hash=context.contract_hash,
            scenario_hash=scenario_hash,
            operation="sha256",
            request_payload_hash=hashlib.sha256(payload).hexdigest(),
            request_sequence_number=request_sequence_number,
        )

    def execute(
        self,
        request: TaskRequest,
        *,
        context: AuthorizedExecutionContext,
        payload: bytes,
        runtime_state: RuntimeState,
    ) -> TaskResponse:
        if runtime_state != RuntimeState.TLS_ACTIVATED:
            raise TaskProtocolError("task request before TLS activation")
        if request.session_id != context.session_id:
            raise TaskProtocolError("wrong task session ID")
        if request.contract_hash != context.contract_hash:
            raise TaskProtocolError("wrong task contract hash")
        if request.request_payload_hash != hashlib.sha256(payload).hexdigest():
            raise TaskProtocolError("modified task payload")
        request_hash = request.request_hash()
        if request_hash in self._requests:
            raise TaskProtocolError("replayed task request")
        self._requests.add(request_hash)
        response_payload = hashlib.sha256(payload).digest()
        response = TaskResponse(
            task_id=request.task_id,
            session_id=request.session_id,
            contract_hash=request.contract_hash,
            status="ok",
            response_payload_hash=hashlib.sha256(response_payload).hexdigest(),
            response_sequence_number=request.request_sequence_number,
        )
        response_hash = response.response_hash()
        if response_hash in self._responses:
            raise TaskProtocolError("replayed task response")
        self._responses.add(response_hash)
        return response
