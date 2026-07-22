"""Decimal-preserving JSON loading and canonical serialization."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from pqtrust_agent.exceptions import CanonicalizationError


def _reject_constant(value: str) -> None:
    raise CanonicalizationError(f"non-finite JSON number is forbidden: {value}")


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise CanonicalizationError(f"duplicate JSON key: {key}")
        seen.add(key)
        result[key] = value
    return result


def load_decimal_json(path: Path) -> Any:
    """Load JSON while preserving all non-integer numbers as ``Decimal``."""

    return json.loads(
        path.read_text(encoding="utf-8"),
        parse_float=Decimal,
        parse_int=int,
        parse_constant=_reject_constant,
        object_pairs_hook=_object_pairs_no_duplicates,
    )


def decimal_to_string(value: Decimal) -> str:
    """Return a canonical non-exponent decimal string."""

    if not value.is_finite():
        raise CanonicalizationError("non-finite Decimal is forbidden")
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def decimal_json_compatible(value: Any) -> Any:
    """Convert Decimals to canonical strings without changing decision values."""

    if isinstance(value, Decimal):
        return decimal_to_string(value)
    if isinstance(value, dict):
        return {str(key): decimal_json_compatible(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [decimal_json_compatible(item) for item in value]
    return value


def dumps_decimal_json(value: Any, *, indent: int | None = None) -> str:
    """Serialize a Decimal-containing object deterministically."""

    return json.dumps(
        decimal_json_compatible(value),
        indent=indent,
        sort_keys=True,
        separators=(",", ": ") if indent is not None else (",", ":"),
    )

