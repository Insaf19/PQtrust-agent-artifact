from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from pqtrust_agent.models import CapabilityManifestPayload, ResourceClass


def make_manifest(**overrides: object) -> CapabilityManifestPayload:
    data = {
        "agent_id": "agent-1",
        "key_id": "key-1",
        "supported_profile_ids": ("P2", "P0"),
        "resource_class": ResourceClass.CLOUD,
        "max_handshake_bytes": None,
        "monotonic_version": 1,
        "issued_at": datetime(2026, 7, 13, 15, 0, tzinfo=timezone(timedelta(hours=2))),
        "expires_at": datetime(2026, 7, 13, 14, 30, tzinfo=UTC),
    }
    data.update(overrides)
    return CapabilityManifestPayload.model_validate(data)


def test_manifest_sorts_unique_profile_ids_and_normalizes_utc() -> None:
    manifest = make_manifest()

    assert manifest.supported_profile_ids == ("P0", "P2")
    assert manifest.issued_at == datetime(2026, 7, 13, 13, 0, tzinfo=UTC)
    assert manifest.expires_at == datetime(2026, 7, 13, 14, 30, tzinfo=UTC)
    assert b"2026-07-13T13:00:00Z" in manifest.canonical_bytes()


def test_manifest_duplicate_capabilities_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_manifest(supported_profile_ids=("P0", "P0"))


def test_manifest_expiry_validation() -> None:
    issued = datetime(2026, 7, 13, 13, 0, tzinfo=UTC)

    with pytest.raises(ValidationError):
        make_manifest(issued_at=issued, expires_at=issued)


def test_manifest_rejects_naive_datetimes() -> None:
    with pytest.raises(ValidationError):
        make_manifest(issued_at=datetime(2026, 7, 13, 13, 0))


def test_manifest_hash_is_stable() -> None:
    assert make_manifest().manifest_hash() == make_manifest().manifest_hash()
