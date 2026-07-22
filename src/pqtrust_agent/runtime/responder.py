"""Stage 7 responder process entry points."""

from __future__ import annotations

from pathlib import Path

from pqtrust_agent.transport.local_channel import (
    LocalSocketEndpoint,
    LocalTcpEndpoint,
    clean_shutdown,
)


def responder_echo_once(socket_path: Path, *, timeout_seconds: float = 5.0) -> None:
    """One-shot local responder used by Stage 7 validation IPC checks."""

    endpoint = LocalSocketEndpoint(socket_path, timeout_seconds=timeout_seconds)
    server = endpoint.listen()
    try:
        conn, _ = server.accept()
        try:
            data = conn.recv(4096)
            conn.sendall(data)
        finally:
            clean_shutdown(conn)
    finally:
        server.close()
        endpoint.cleanup()


def responder_tcp_echo_once(port: int, *, timeout_seconds: float = 5.0) -> None:
    endpoint = LocalTcpEndpoint(port, timeout_seconds=timeout_seconds)
    server = endpoint.listen()
    try:
        conn, _ = server.accept()
        try:
            data = conn.recv(4096)
            conn.sendall(data)
        finally:
            clean_shutdown(conn)
    finally:
        server.close()
