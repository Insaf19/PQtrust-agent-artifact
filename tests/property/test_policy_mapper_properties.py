from __future__ import annotations

from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from pqtrust_agent.models import (
    CONFIDENTIALITY_HORIZON_RANK,
    OPERATIONAL_IMPACT_RANK,
    TASK_SENSITIVITY_RANK,
    ConfidentialityHorizon,
    NetworkClass,
    OperationalImpact,
    TaskDescriptor,
    TaskSensitivity,
    requirement_dominates,
)
from pqtrust_agent.policy.loader import load_agent_policy
from pqtrust_agent.policy.mapper import derive_requirement

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY = load_agent_policy(REPO_ROOT / "configs/policies/cloud_orchestrator.yaml")


@given(
    sensitivity=st.sampled_from(tuple(TaskSensitivity)),
    impact=st.sampled_from(tuple(OperationalImpact)),
    horizon=st.sampled_from(tuple(ConfidentialityHorizon)),
    delegation=st.integers(min_value=0, max_value=7),
    seconds=st.integers(min_value=1, max_value=86399),
    network=st.sampled_from(tuple(NetworkClass)),
    org=st.sampled_from(("public-tool", "enterprise-sensitive", "critical-control")),
)
def test_mapper_monotonicity_adjacent_property(
    sensitivity: TaskSensitivity,
    impact: OperationalImpact,
    horizon: ConfidentialityHorizon,
    delegation: int,
    seconds: int,
    network: NetworkClass,
    org: str,
) -> None:
    sensitivities = tuple(sorted(TaskSensitivity, key=lambda item: TASK_SENSITIVITY_RANK[item]))
    impacts = tuple(sorted(OperationalImpact, key=lambda item: OPERATIONAL_IMPACT_RANK[item]))
    horizons = tuple(
        sorted(ConfidentialityHorizon, key=lambda item: CONFIDENTIALITY_HORIZON_RANK[item])
    )
    low = TaskDescriptor(
        sensitivity=sensitivity,
        operational_impact=impact,
        confidentiality_horizon=horizon,
        delegation_depth=delegation,
        expected_session_seconds=seconds,
        network_class=network,
        organization_policy_class=org,
    )
    high = low.model_copy(
        update={
            "sensitivity": sensitivities[
                min(sensitivities.index(sensitivity) + 1, len(sensitivities) - 1)
            ],
            "operational_impact": impacts[min(impacts.index(impact) + 1, len(impacts) - 1)],
            "confidentiality_horizon": horizons[
                min(horizons.index(horizon) + 1, len(horizons) - 1)
            ],
            "delegation_depth": delegation + 1,
            "expected_session_seconds": seconds + 1,
        }
    )

    assert requirement_dominates(
        derive_requirement(POLICY, high).final_requirement,
        derive_requirement(POLICY, low).final_requirement,
    )
