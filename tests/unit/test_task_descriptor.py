from __future__ import annotations

import pytest
from pydantic import ValidationError

from pqtrust_agent.models import (
    ConfidentialityHorizon,
    NetworkClass,
    OperationalImpact,
    TaskDescriptor,
    TaskSensitivity,
)


def make_descriptor(**overrides: object) -> TaskDescriptor:
    data = {
        "sensitivity": TaskSensitivity.INTERNAL,
        "operational_impact": OperationalImpact.BUSINESS_ACTION,
        "confidentiality_horizon": ConfidentialityHorizon.MEDIUM,
        "delegation_depth": 2,
        "expected_session_seconds": 900,
        "network_class": NetworkClass.ENTERPRISE_WAN,
        "organization_policy_class": "org.policy_1",
    }
    data.update(overrides)
    return TaskDescriptor.model_validate(data)


@pytest.mark.parametrize("depth", [0, 8])
def test_task_descriptor_delegation_boundaries(depth: int) -> None:
    assert make_descriptor(delegation_depth=depth).delegation_depth == depth


@pytest.mark.parametrize("depth", [-1, 9])
def test_task_descriptor_rejects_invalid_delegation_depth(depth: int) -> None:
    with pytest.raises(ValidationError):
        make_descriptor(delegation_depth=depth)


@pytest.mark.parametrize("seconds", [1, 86400])
def test_task_descriptor_session_boundaries(seconds: int) -> None:
    assert make_descriptor(expected_session_seconds=seconds).expected_session_seconds == seconds


@pytest.mark.parametrize("seconds", [0, 86401])
def test_task_descriptor_rejects_invalid_session_seconds(seconds: int) -> None:
    with pytest.raises(ValidationError):
        make_descriptor(expected_session_seconds=seconds)


@pytest.mark.parametrize("policy_class", ["", "bad space", "bad/slash", "x" * 65])
def test_task_descriptor_rejects_invalid_organization_policy_identifiers(
    policy_class: str,
) -> None:
    with pytest.raises(ValidationError):
        make_descriptor(organization_policy_class=policy_class)


def test_task_descriptor_canonical_hash_is_stable() -> None:
    first = make_descriptor()
    second = make_descriptor()

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.context_hash() == second.context_hash()
    assert len(first.context_hash()) == 64
