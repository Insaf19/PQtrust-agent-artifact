"""Stage 7 initiator process entry points."""

from __future__ import annotations

from pathlib import Path

from pqtrust_agent.transport.local_channel import (
    LocalSocketEndpoint,
    LocalTcpEndpoint,
    clean_shutdown,
)


def initiator_probe(socket_path: Path, payload: bytes, *, timeout_seconds: float = 5.0) -> bytes:
    """Small process-safe probe used by validation to prove local IPC works."""

    endpoint = LocalSocketEndpoint(socket_path, timeout_seconds=timeout_seconds)
    sock = endpoint.connect()
    try:
        sock.sendall(payload)
        return sock.recv(4096)
    finally:
        clean_shutdown(sock)


def initiator_tcp_probe(port: int, payload: bytes, *, timeout_seconds: float = 5.0) -> bytes:
    endpoint = LocalTcpEndpoint(port, timeout_seconds=timeout_seconds)
    sock = endpoint.connect()
    try:
        sock.sendall(payload)
        return sock.recv(4096)
    finally:
        clean_shutdown(sock)
