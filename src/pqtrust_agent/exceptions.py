"""Project-specific exceptions for PQTrust-Agent model validation."""

from __future__ import annotations


class PQTrustError(Exception):
    """Base exception for PQTrust-Agent errors."""


class CanonicalizationError(PQTrustError, ValueError):
    """Raised when a value cannot be converted to signed canonical JSON."""


class CatalogValidationError(PQTrustError, ValueError):
    """Raised when a trust-profile catalog is invalid."""


class PolicyValidationError(PQTrustError, ValueError):
    """Raised when a policy-stage configuration is invalid."""


class PolicyCompilationError(PQTrustError, RuntimeError):
    """Raised when the deterministic policy compiler cannot complete."""
