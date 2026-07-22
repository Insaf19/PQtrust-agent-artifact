"""Typed selector-stage result models."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.evidence.decimal_json import decimal_json_compatible
from pqtrust_agent.models.compilation import ProfileId

SELECTION_HASH_DOMAIN = "PQTrust.BilateralSelection.v1"
SELECTOR_IMPLEMENTATION_VERSION: Literal["0.4.0"] = "0.4.0"


class SelectionMode(StrEnum):
    """Structural selector mode derived from common-safe and Pareto sizes."""

    SINGLETON_COMMON_SAFE_SET = "singleton_common_safe_set"
    PARETO_FRONTIER_COLLAPSE = "pareto_frontier_collapse"
    BILATERAL_MINIMAX_REGRET = "bilateral_minimax_regret"


def classify_selection_mode(
    *,
    common_safe_candidate_count: int,
    pareto_candidate_count: int,
) -> SelectionMode:
    """Classify whether minimax regret is structurally exercised."""

    if common_safe_candidate_count < 1:
        raise ValueError("common safe set must not be empty")
    if pareto_candidate_count < 1:
        raise ValueError("Pareto frontier must not be empty")
    if pareto_candidate_count > common_safe_candidate_count:
        raise ValueError("Pareto frontier cannot exceed common safe set")
    if common_safe_candidate_count == 1:
        return SelectionMode.SINGLETON_COMMON_SAFE_SET
    if pareto_candidate_count == 1:
        return SelectionMode.PARETO_FRONTIER_COLLAPSE
    return SelectionMode.BILATERAL_MINIMAX_REGRET


class DecimalModel(BaseModel):
    """Base model allowing Decimal values and forbidding unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)


class BilateralSelectionInput(DecimalModel):
    selector_schema_version: Literal["1.0"] = "1.0"
    scenario_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    task_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    catalog_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    initiator_agent_id: str
    responder_agent_id: str
    initiator_policy_compilation_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    responder_policy_compilation_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    initiator_preference_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    responder_preference_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    calibrated_cost_evidence_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    evaluation_time: datetime

    @field_validator("evaluation_time", mode="after")
    @classmethod
    def _normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation_time must be timezone-aware")
        return value.astimezone(UTC)


class BilateralCandidateEvaluation(DecimalModel):
    profile_id: ProfileId
    raw_measured_cost_vector: dict[str, Decimal]
    normalized_cost_vector: dict[str, Decimal]
    initiator_weighted_components: dict[str, Decimal] | None = None
    responder_weighted_components: dict[str, Decimal] | None = None
    initiator_cost: Decimal | None = None
    responder_cost: Decimal | None = None
    initiator_regret: Decimal | None = None
    responder_regret: Decimal | None = None
    maximum_regret: Decimal | None = None
    total_regret: Decimal | None = None
    pareto_status: Literal["frontier", "dominated"]
    dominating_profile_ids: tuple[ProfileId, ...] = ()
    dominated_dimensions: dict[ProfileId, tuple[str, ...]] = Field(default_factory=dict)
    domination_explanation: dict[str, Any] | None = None
    eligible_for_regret_computation: bool
    regret_exclusion_reason: str | None = None


class BilateralSelectionResult(DecimalModel):
    selector_schema_version: Literal["1.0"] = "1.0"
    selector_implementation_version: Literal["0.4.0"] = SELECTOR_IMPLEMENTATION_VERSION
    scenario_id: str
    initiator_local_safe_set: tuple[ProfileId, ...]
    responder_local_safe_set: tuple[ProfileId, ...]
    common_safe_set: tuple[ProfileId, ...]
    pareto_frontier: tuple[ProfileId, ...]
    removed_as_dominated: tuple[ProfileId, ...]
    selected_profile_id: ProfileId
    candidates: tuple[BilateralCandidateEvaluation, ...]
    common_safe_candidate_count: int
    pareto_candidate_count: int
    selection_mode: SelectionMode
    minimax_regret_exercised: bool
    bilateral_tradeoff_present: bool
    frontier_collapsed: bool
    deterministic_tie_break_trace: tuple[str, ...]
    absolute_timing_stability_passed: bool
    paired_relative_timing_stability_passed: bool
    relative_cost_usable_for_selector: bool
    selection_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @staticmethod
    def compute_hash_payload(**kwargs: Any) -> dict[str, Any]:
        return dict(kwargs)

    def canonical_payload(self) -> dict[str, Any]:
        return cast(dict[str, Any], decimal_json_compatible(self.model_dump(mode="python")))


def selection_hash(payload: dict[str, Any]) -> str:
    """Return the domain-separated selector result hash."""

    return domain_separated_sha256(SELECTION_HASH_DOMAIN, decimal_json_compatible(payload))
