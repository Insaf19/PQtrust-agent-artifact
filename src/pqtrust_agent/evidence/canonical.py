"""RFC 8785 canonicalization and domain-separated hashing."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any, cast

import rfc8785
from pydantic import BaseModel

from pqtrust_agent.exceptions import CanonicalizationError

DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _datetime_to_utc_z(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalizationError("datetimes must be timezone-aware")
    normalized = value.astimezone(UTC)
    return normalized.isoformat().replace("+00:00", "Z")


def to_json_compatible(value: Any) -> object:
    """Convert supported typed values to JSON-compatible values for signing."""

    if isinstance(value, BaseModel):
        return to_json_compatible(
            value.model_dump(mode="json", by_alias=True, exclude_none=False)
        )
    if hasattr(value, "__pydantic_serializer__") and hasattr(value, "__dataclass_fields__"):
        serializer = value.__pydantic_serializer__
        return to_json_compatible(serializer.to_python(value, mode="json", by_alias=True))
    if isinstance(value, Enum):
        enum_value = value.value
        if not isinstance(enum_value, str):
            raise CanonicalizationError("only string-valued enums are supported")
        return enum_value
    if isinstance(value, datetime):
        return _datetime_to_utc_z(value)
    if isinstance(value, str) or value is None:
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError("NaN and infinity are forbidden")
        raise CanonicalizationError("floating-point values are forbidden")
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("dictionary keys must be strings")
            normalized[key] = to_json_compatible(item)
        return normalized
    if isinstance(value, (set, frozenset)):
        return sorted(
            (to_json_compatible(item) for item in value),
            key=lambda item: rfc8785.dumps(cast(Any, item)),
        )
    if isinstance(value, tuple | list):
        return [to_json_compatible(item) for item in value]
    raise CanonicalizationError(f"unsupported value for canonicalization: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes for a supported protocol value."""

    try:
        encoded = rfc8785.dumps(cast(Any, to_json_compatible(value)))
    except CanonicalizationError:
        raise
    except Exception as exc:
        raise CanonicalizationError(str(exc)) from exc
    return encoded


def domain_separated_sha256(domain: str, value: Any) -> str:
    """Hash canonical JSON as ``UTF8(domain) || 0x00 || canonical_bytes``."""

    if DOMAIN_RE.fullmatch(domain) is None:
        raise CanonicalizationError("domain must match ^[A-Za-z0-9._-]+$")
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(canonicalize(value))
    return digest.hexdigest()
