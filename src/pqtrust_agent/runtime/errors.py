"""Runtime exceptions for Stage 7 fail-closed behavior."""

from __future__ import annotations


class RuntimeStateError(RuntimeError):
    """Raised for illegal runtime state transitions."""


class DiscoveryError(RuntimeError):
    """Raised for invalid local agent discovery data."""


class ExecutionGateError(RuntimeError):
    """Raised when execution authorization fails closed."""


class TaskProtocolError(RuntimeError):
    """Raised for task ordering, binding, or replay errors."""
