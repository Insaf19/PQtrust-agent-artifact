"""Agent policy models for deterministic local compilation."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.common import (
    CONFIDENTIALITY_HORIZON_RANK,
    OPERATIONAL_IMPACT_RANK,
    TASK_SENSITIVITY_RANK,
    ConfidentialityHorizon,
    ContractEvidenceMode,
    EndpointAuthenticationMode,
    FallbackRule,
    LeaseStrictness,
    NetworkClass,
    OperationalImpact,
    ResumptionRule,
    TaskSensitivity,
    ThreatClass,
)
from pqtrust_agent.models.profile import PROFILE_ID_RE
from pqtrust_agent.models.requirements import AssuranceRequirement, requirement_join
from pqtrust_agent.models.task import PolicyClass, TaskDescriptor

AGENT_POLICY_HASH_DOMAIN = "PQTrust.AgentPolicy.v1"
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")]
ProfileId = Annotated[str, Field(pattern=PROFILE_ID_RE)]
RuleId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")]


def _profile_sort_key(profile_id: str) -> tuple[int, str]:
    suffix = profile_id[1:]
    return (int(suffix), profile_id) if suffix.isdigit() else (10**9, profile_id)


def _sorted_unique_strings(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple | set | frozenset):
        raise TypeError(f"{field_name} must be a sequence")
    items = tuple(str(item) for item in value)
    if len(items) != len(set(items)):
        raise ValueError(f"{field_name} must not contain duplicates")
    return tuple(sorted(items))


class TaskRuleCondition(BaseModel):
    """Monotone lower-bound task predicates plus exact unordered class filters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    minimum_sensitivity: TaskSensitivity | None = None
    minimum_operational_impact: OperationalImpact | None = None
    minimum_confidentiality_horizon: ConfidentialityHorizon | None = None
    minimum_delegation_depth: Annotated[int | None, Field(default=None, ge=0, le=8, strict=True)]
    minimum_expected_session_seconds: Annotated[
        int | None, Field(default=None, ge=1, le=86400, strict=True)
    ]
    network_classes: tuple[NetworkClass, ...] | None = None
    organization_policy_classes: tuple[PolicyClass, ...] | None = None

    @field_validator("network_classes", mode="before")
    @classmethod
    def _coerce_network_classes(cls, value: Any) -> tuple[NetworkClass, ...] | None:
        if value is None:
            return None
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("network_classes must be a sequence")
        items = tuple(NetworkClass(item) for item in value)
        if len(items) != len(set(items)):
            raise ValueError("network_classes must be unique")
        return tuple(sorted(items, key=lambda item: item.value))

    @field_validator("organization_policy_classes", mode="before")
    @classmethod
    def _coerce_policy_classes(cls, value: Any) -> tuple[str, ...] | None:
        if value is None:
            return None
        return _sorted_unique_strings(value, "organization_policy_classes")

    def matches(self, task: TaskDescriptor) -> bool:
        """Return true when all specified predicates match ``task``."""

        return (
            (
                self.minimum_sensitivity is None
                or TASK_SENSITIVITY_RANK[task.sensitivity]
                >= TASK_SENSITIVITY_RANK[self.minimum_sensitivity]
            )
            and (
                self.minimum_operational_impact is None
                or OPERATIONAL_IMPACT_RANK[task.operational_impact]
                >= OPERATIONAL_IMPACT_RANK[self.minimum_operational_impact]
            )
            and (
                self.minimum_confidentiality_horizon is None
                or CONFIDENTIALITY_HORIZON_RANK[task.confidentiality_horizon]
                >= CONFIDENTIALITY_HORIZON_RANK[self.minimum_confidentiality_horizon]
            )
            and (
                self.minimum_delegation_depth is None
                or task.delegation_depth >= self.minimum_delegation_depth
            )
            and (
                self.minimum_expected_session_seconds is None
                or task.expected_session_seconds >= self.minimum_expected_session_seconds
            )
            and (
                self.network_classes is None or task.network_class in self.network_classes
            )
            and (
                self.organization_policy_classes is None
                or task.organization_policy_class in self.organization_policy_classes
            )
        )


class RequirementContribution(BaseModel):
    """Optional requirement fields that strengthen by join."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_establishment_threats: frozenset[ThreatClass] | None = None
    endpoint_authentication_threats: frozenset[ThreatClass] | None = None
    contract_evidence_threats: frozenset[ThreatClass] | None = None
    fallback_rule: FallbackRule | None = None
    resumption_rule: ResumptionRule | None = None
    lease_strictness: LeaseStrictness | None = None

    @field_validator(
        "key_establishment_threats",
        "endpoint_authentication_threats",
        "contract_evidence_threats",
        mode="before",
    )
    @classmethod
    def _coerce_optional_threat_sets(cls, value: Any) -> frozenset[ThreatClass] | None:
        if value is None:
            return None
        if isinstance(value, (set, list, tuple, frozenset)):
            return frozenset(ThreatClass(item) for item in value)
        raise TypeError("threat contributions must be set-like collections")

    @field_serializer(
        "key_establishment_threats",
        "endpoint_authentication_threats",
        "contract_evidence_threats",
    )
    def _serialize_optional_threat_sets(
        self,
        value: frozenset[ThreatClass] | None,
    ) -> tuple[str, ...] | None:
        if value is None:
            return None
        return tuple(sorted(threat.value for threat in value))

    @model_validator(mode="after")
    def _validate_non_empty(self) -> RequirementContribution:
        if all(
            value is None
            for value in (
                self.key_establishment_threats,
                self.endpoint_authentication_threats,
                self.contract_evidence_threats,
                self.fallback_rule,
                self.resumption_rule,
                self.lease_strictness,
            )
        ):
            raise ValueError("at least one contribution field must be supplied")
        return self

    def apply_to(self, requirement: AssuranceRequirement) -> AssuranceRequirement:
        """Strengthen ``requirement`` with this contribution."""

        contributed = AssuranceRequirement(
            key_establishment_threats=self.key_establishment_threats
            if self.key_establishment_threats is not None
            else frozenset(),
            endpoint_authentication_threats=self.endpoint_authentication_threats
            if self.endpoint_authentication_threats is not None
            else frozenset(),
            contract_evidence_threats=self.contract_evidence_threats
            if self.contract_evidence_threats is not None
            else frozenset(),
            fallback_rule=self.fallback_rule or requirement.fallback_rule,
            resumption_rule=self.resumption_rule or requirement.resumption_rule,
            lease_strictness=self.lease_strictness or requirement.lease_strictness,
        )
        return requirement_join(requirement, contributed)


class PolicyRule(BaseModel):
    """One named monotone policy rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: RuleId
    description: Annotated[str, Field(min_length=1, max_length=1200)]
    condition: TaskRuleCondition
    contribution: RequirementContribution


class AgentPolicy(BaseModel):
    """Versioned private agent policy for local profile compilation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_schema_version: Literal["1.0"] = "1.0"
    policy_id: Identifier
    policy_version: Annotated[int, Field(gt=0, strict=True)]
    agent_id: Identifier
    catalog_version: Literal["1.0"]
    base_requirement: AssuranceRequirement
    allowed_profile_ids: tuple[ProfileId, ...]
    denied_profile_ids: tuple[ProfileId, ...] = ()
    permitted_endpoint_authentication_modes: tuple[EndpointAuthenticationMode, ...] | None = None
    permitted_contract_evidence_modes: tuple[ContractEvidenceMode, ...] | None = None
    rules: tuple[PolicyRule, ...] = ()
    solver_timeout_ms: Annotated[int, Field(default=5000, gt=0, le=60000, strict=True)] = 5000

    @field_validator("allowed_profile_ids", "denied_profile_ids", mode="before")
    @classmethod
    def _coerce_profile_ids(cls, value: Any) -> tuple[str, ...]:
        ids = _sorted_unique_strings(value, "profile_ids")
        return tuple(sorted(ids, key=_profile_sort_key))

    @field_validator("permitted_endpoint_authentication_modes", mode="before")
    @classmethod
    def _coerce_endpoint_modes(
        cls, value: Any
    ) -> tuple[EndpointAuthenticationMode, ...] | None:
        if value is None:
            return None
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("permitted_endpoint_authentication_modes must be a sequence")
        modes = tuple(EndpointAuthenticationMode(item) for item in value)
        if len(modes) != len(set(modes)):
            raise ValueError("permitted_endpoint_authentication_modes must be unique")
        return tuple(sorted(modes, key=lambda item: item.value))

    @field_validator("permitted_contract_evidence_modes", mode="before")
    @classmethod
    def _coerce_evidence_modes(cls, value: Any) -> tuple[ContractEvidenceMode, ...] | None:
        if value is None:
            return None
        if not isinstance(value, list | tuple | set | frozenset):
            raise TypeError("permitted_contract_evidence_modes must be a sequence")
        modes = tuple(ContractEvidenceMode(item) for item in value)
        if len(modes) != len(set(modes)):
            raise ValueError("permitted_contract_evidence_modes must be unique")
        return tuple(sorted(modes, key=lambda item: item.value))

    @field_validator("rules", mode="before")
    @classmethod
    def _coerce_rules(cls, value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if not isinstance(value, list | tuple):
            raise TypeError("rules must be a sequence")
        return tuple(
            sorted(
                value,
                key=lambda item: item.get("rule_id", "")
                if isinstance(item, dict)
                else item.rule_id,
            )
        )

    @model_validator(mode="after")
    def _validate_policy(self) -> AgentPolicy:
        overlap = set(self.allowed_profile_ids) & set(self.denied_profile_ids)
        if overlap:
            raise ValueError(f"allowed and denied profile IDs overlap: {tuple(sorted(overlap))!r}")
        rule_ids = tuple(rule.rule_id for rule in self.rules)
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule IDs must be unique inside one policy")
        if tuple(rule_ids) != tuple(sorted(rule_ids)):
            raise ValueError("rules must be in canonical rule_id order")
        return self

    def canonical_payload(self) -> object:
        """Return the JSON-compatible policy payload."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes."""

        return canonicalize(self)

    def policy_hash(self) -> str:
        """Return the domain-separated policy hash."""

        return domain_separated_sha256(AGENT_POLICY_HASH_DOMAIN, self)
