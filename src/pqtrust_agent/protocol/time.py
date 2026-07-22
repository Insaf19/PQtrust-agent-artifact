"""Explicit protocol time handling.

Contract leases are inclusive at ``issued_at`` and exclusive at ``expires_at``:
``issued_at <= t < expires_at``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pqtrust_agent.protocol.errors import ProtocolTimeError


def current_utc_time() -> datetime:
    """Return production wall-clock time for adapters that explicitly need it."""

    return datetime.now(UTC)


def require_utc_aware(value: datetime, *, phase: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProtocolTimeError(
            "TIMEZONE_NAIVE",
            "reference time must be timezone-aware UTC",
            phase=phase,
            reference_time=value,
        )
    return value.astimezone(UTC)


def validate_time_interval(
    *,
    issued_at: datetime,
    expires_at: datetime,
    phase: str,
) -> tuple[datetime, datetime]:
    issued = require_utc_aware(issued_at, phase=phase)
    expires = require_utc_aware(expires_at, phase=phase)
    if expires <= issued:
        raise ProtocolTimeError(
            "INVALID_TIME_INTERVAL",
            "expires_at must be later than issued_at",
            phase=phase,
            reference_time=issued,
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )
    return issued, expires


def require_contract_active(
    *,
    issued_at: datetime,
    expires_at: datetime,
    activation_time: datetime,
    phase: str,
) -> datetime:
    issued, expires = validate_time_interval(
        issued_at=issued_at,
        expires_at=expires_at,
        phase=phase,
    )
    activation = require_utc_aware(activation_time, phase=phase)
    if activation < issued:
        raise ProtocolTimeError(
            "CONTRACT_NOT_YET_VALID",
            "contract activation is before issued_at",
            phase=phase,
            reference_time=activation,
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )
    if activation >= expires:
        raise ProtocolTimeError(
            "CONTRACT_EXPIRED",
            "contract activation is at or after expires_at",
            phase=phase,
            reference_time=activation,
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )
    return activation


def require_proposal_active(
    *,
    evaluation_time: datetime,
    expires_at: datetime,
    verification_time: datetime,
    phase: str,
) -> datetime:
    start, expires = validate_time_interval(
        issued_at=evaluation_time,
        expires_at=expires_at,
        phase=phase,
    )
    verification = require_utc_aware(verification_time, phase=phase)
    if verification < start:
        raise ProtocolTimeError(
            "CONTRACT_NOT_YET_VALID",
            "proposal verification is before evaluation_time",
            phase=phase,
            reference_time=verification,
            evaluation_time=start.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )
    if verification >= expires:
        raise ProtocolTimeError(
            "PROPOSAL_EXPIRED",
            "proposal verification is at or after expires_at",
            phase=phase,
            reference_time=verification,
            evaluation_time=start.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )
    return verification
