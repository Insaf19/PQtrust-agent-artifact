from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.exceptions import CanonicalizationError
from pqtrust_agent.models import ResourceClass


def test_canonical_bytes_are_independent_of_dictionary_insertion_order() -> None:
    left = {"b": 2, "a": {"z": True, "y": None}}
    right = {"a": {"y": None, "z": True}, "b": 2}

    assert canonicalize(left) == canonicalize(right)


def test_canonical_bytes_are_independent_of_set_ordering() -> None:
    assert canonicalize({"values": {"b", "a"}}) == canonicalize({"values": {"a", "b"}})


def test_domain_separation_changes_hashes() -> None:
    value = {"a": 1}

    assert domain_separated_sha256("PQTrust.A", value) != domain_separated_sha256(
        "PQTrust.B",
        value,
    )


@pytest.mark.parametrize("value", [1.25, float("nan"), float("inf"), -float("inf")])
def test_floats_nan_and_infinity_are_rejected(value: float) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"value": value})


def test_non_string_dictionary_keys_are_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "value"})


def test_boolean_values_remain_booleans() -> None:
    payload = to_json_compatible({"flag": True, "count": 1})

    assert payload == {"flag": True, "count": 1}
    assert canonicalize(payload) == b'{"count":1,"flag":true}'


def test_datetimes_normalize_to_utc_z() -> None:
    dt = datetime(2026, 7, 13, 15, 30, tzinfo=timezone(timedelta(hours=2)))

    assert to_json_compatible({"issued_at": dt}) == {"issued_at": "2026-07-13T13:30:00Z"}


def test_enums_become_string_values() -> None:
    assert to_json_compatible(ResourceClass.CLOUD) == "cloud"
