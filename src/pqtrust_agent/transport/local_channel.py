"""Local laboratory process transport for Stage 7."""

from __future__ import annotations

import os
import socket
import time
from contextlib import suppress
from pathlib import Path

from pqtrust_agent.transport.framing import FrameError


class LocalChannelError(RuntimeError):
    """Raised for local socket failures."""


class LocalSocketEndpoint:
    """Bounded Unix-domain socket endpoint."""

    def __init__(self, socket_path: Path, *, timeout_seconds: float = 5.0) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def listen(self) -> socket.socket:
        if os.name == "posix":
            self.socket_path.parent.mkdir(parents=True, exist_ok=True)
            with suppress(FileNotFoundError):
                self.socket_path.unlink()
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.settimeout(self.timeout_seconds)
            server.bind(str(self.socket_path))
            server.listen(1)
            return server
        raise LocalChannelError("Unix domain sockets are required for this endpoint")

    def connect(self) -> socket.socket:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout_seconds)
        client.connect(str(self.socket_path))
        return client

    def cleanup(self) -> None:
        with suppress(FileNotFoundError):
            self.socket_path.unlink()


class LocalTcpEndpoint:
    """Bounded localhost TCP endpoint used when Unix sockets are unavailable."""

    def __init__(self, port: int, *, timeout_seconds: float = 5.0) -> None:
        if port <= 0 or port >= 65536:
            raise ValueError("port must be unprivileged and valid")
        self.port = port
        self.timeout_seconds = timeout_seconds

    def listen(self) -> socket.socket:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(self.timeout_seconds)
        server.bind(("127.0.0.1", self.port))
        server.listen(1)
        return server

    def connect(self) -> socket.socket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(self.timeout_seconds)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                client.connect(("127.0.0.1", self.port))
                return client
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    client.close()
                    raise
                time.sleep(0.01)


def read_exact(sock: socket.socket, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be nonnegative")
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise FrameError("truncated socket read")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def clean_shutdown(sock: socket.socket) -> None:
    with suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)
    sock.close()
