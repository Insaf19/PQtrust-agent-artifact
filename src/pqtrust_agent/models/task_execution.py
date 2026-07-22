"""Deterministic Stage 7 task protocol models."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.models.protocol import SESSION_ID_RE, SHA256_HEX_RE


class TaskRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_version: Literal["1.0"] = "1.0"
    task_id: str
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    contract_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    scenario_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    operation: Literal["sha256"]
    request_payload_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    request_sequence_number: Annotated[int, Field(ge=0, strict=True)]

    def request_hash(self) -> str:
        return domain_separated_sha256("PQTrust.TaskRequest.v1", self)


class TaskResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_version: Literal["1.0"] = "1.0"
    task_id: str
    session_id: Annotated[str, Field(pattern=SESSION_ID_RE)]
    contract_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    status: Literal["ok", "rejected"]
    response_payload_hash: Annotated[str, Field(pattern=SHA256_HEX_RE)]
    response_sequence_number: Annotated[int, Field(ge=0, strict=True)]

    def response_hash(self) -> str:
        return domain_separated_sha256("PQTrust.TaskResponse.v1", self)
