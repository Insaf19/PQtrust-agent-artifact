"""Deterministic length-prefixed Stage 7 message framing."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Mapping
from typing import Any, Literal

from pqtrust_agent.evidence.canonical import canonicalize
from pqtrust_agent.models.transport import FrameHeader, MessageType

MAX_FRAME_SIZE = 1024 * 1024
_PREFIX = struct.Struct("!I")


class FrameError(ValueError):
    """Raised for invalid frame bytes."""


def _payload_hash(payload_bytes: bytes) -> str:
    return hashlib.sha256(payload_bytes).hexdigest()


def encode_frame(
    *,
    protocol_version: Literal["1.0"],
    message_type: MessageType,
    session_id: str,
    sequence_number: int,
    payload: Mapping[str, Any],
    max_frame_size: int = MAX_FRAME_SIZE,
) -> bytes:
    payload_bytes = canonicalize(dict(payload))
    header = FrameHeader(
        protocol_version=protocol_version,
        message_type=message_type,
        session_id=session_id,
        sequence_number=sequence_number,
        payload_length=len(payload_bytes),
        payload_hash=_payload_hash(payload_bytes),
    )
    envelope = canonicalize(
        {
            "header": header.model_dump(mode="json"),
            "payload": dict(payload),
        }
    )
    total_length = len(envelope)
    if total_length > max_frame_size:
        raise FrameError("oversized frame")
    return _PREFIX.pack(total_length) + envelope


def decode_frame(
    data: bytes,
    *,
    max_frame_size: int = MAX_FRAME_SIZE,
) -> tuple[FrameHeader, dict[str, Any]]:
    if len(data) < _PREFIX.size:
        raise FrameError("truncated frame prefix")
    (length,) = _PREFIX.unpack(data[: _PREFIX.size])
    if length > max_frame_size:
        raise FrameError("oversized frame")
    expected_total = _PREFIX.size + length
    if len(data) < expected_total:
        raise FrameError("truncated frame")
    if len(data) > expected_total:
        raise FrameError("trailing bytes after frame")
    import json

    try:
        envelope = json.loads(data[_PREFIX.size : expected_total].decode("utf-8"))
    except Exception as exc:
        raise FrameError("invalid frame JSON") from exc
    if not isinstance(envelope, dict):
        raise FrameError("frame envelope must be an object")
    header_raw = envelope.get("header")
    payload = envelope.get("payload")
    if not isinstance(header_raw, dict) or not isinstance(payload, dict):
        raise FrameError("frame header and payload must be objects")
    try:
        header = FrameHeader.model_validate(header_raw)
    except Exception as exc:
        raise FrameError(str(exc)) from exc
    payload_bytes = canonicalize(payload)
    if len(payload_bytes) != header.payload_length:
        raise FrameError("payload length mismatch")
    if _payload_hash(payload_bytes) != header.payload_hash:
        raise FrameError("payload hash mismatch")
    return header, payload


class SequenceValidator:
    """Monotonic frame sequence checker."""

    def __init__(self) -> None:
        self._next = 0
        self._seen: set[int] = set()

    def observe(self, header: FrameHeader) -> None:
        sequence = header.sequence_number
        if sequence in self._seen:
            raise FrameError("duplicate sequence number")
        if sequence != self._next:
            raise FrameError("skipped sequence number")
        self._seen.add(sequence)
        self._next += 1
