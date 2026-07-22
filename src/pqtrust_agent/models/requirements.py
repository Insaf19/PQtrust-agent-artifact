"""Assurance requirement model and order operations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    domain_separated_sha256,
    to_json_compatible,
)
from pqtrust_agent.models.common import (
    FALLBACK_RULE_RANK,
    LEASE_STRICTNESS_RANK,
    RESUMPTION_RULE_RANK,
    AssuranceVector,
    FallbackRule,
    LeaseStrictness,
    ResumptionRule,
    ThreatClass,
)

ASSURANCE_REQUIREMENT_HASH_DOMAIN = "PQTrust.AssuranceRequirement.v1"


class AssuranceRequirement(BaseModel):
    """Minimum assurance required by one agent for one task."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_establishment_threats: frozenset[ThreatClass] = Field(
        description="Required key-establishment threat coverage."
    )
    endpoint_authentication_threats: frozenset[ThreatClass] = Field(
        description="Required endpoint-authentication threat coverage."
    )
    contract_evidence_threats: frozenset[ThreatClass] = Field(
        description="Required contract-evidence threat coverage."
    )
    fallback_rule: FallbackRule = Field(description="Minimum fallback strictness.")
    resumption_rule: ResumptionRule = Field(description="Minimum resumption strictness.")
    lease_strictness: LeaseStrictness = Field(description="Minimum lease strictness.")

    @field_validator(
        "key_establishment_threats",
        "endpoint_authentication_threats",
        "contract_evidence_threats",
        mode="before",
    )
    @classmethod
    def _coerce_threat_sets(cls, value: Any) -> frozenset[ThreatClass]:
        if isinstance(value, frozenset) and all(isinstance(item, ThreatClass) for item in value):
            return value
        if isinstance(value, (set, list, tuple, frozenset)):
            return frozenset(ThreatClass(item) for item in value)
        raise TypeError("threat dimensions must be set-like collections")

    @field_serializer(
        "key_establishment_threats",
        "endpoint_authentication_threats",
        "contract_evidence_threats",
    )
    def _serialize_threat_sets(self, value: frozenset[ThreatClass]) -> tuple[str, ...]:
        return tuple(sorted(threat.value for threat in value))

    def as_assurance_vector(self) -> AssuranceVector:
        """Return this requirement as an assurance vector."""

        return AssuranceVector(
            key_establishment_threats=self.key_establishment_threats,
            endpoint_authentication_threats=self.endpoint_authentication_threats,
            contract_evidence_threats=self.contract_evidence_threats,
            fallback_rule=self.fallback_rule,
            resumption_rule=self.resumption_rule,
            lease_strictness=self.lease_strictness,
        )

    def canonical_payload(self) -> object:
        """Return the JSON-compatible requirement payload."""

        return to_json_compatible(self)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 canonical JSON bytes."""

        return canonicalize(self)

    def requirement_hash(self) -> str:
        """Return the domain-separated requirement hash."""

        return domain_separated_sha256(ASSURANCE_REQUIREMENT_HASH_DOMAIN, self)


def requirement_dominates(left: AssuranceRequirement, right: AssuranceRequirement) -> bool:
    """Return true when ``left`` is component-wise at least as strong as ``right``."""

    return (
        left.key_establishment_threats.issuperset(right.key_establishment_threats)
        and left.endpoint_authentication_threats.issuperset(
            right.endpoint_authentication_threats
        )
        and left.contract_evidence_threats.issuperset(right.contract_evidence_threats)
        and FALLBACK_RULE_RANK[left.fallback_rule] >= FALLBACK_RULE_RANK[right.fallback_rule]
        and RESUMPTION_RULE_RANK[left.resumption_rule]
        >= RESUMPTION_RULE_RANK[right.resumption_rule]
        and LEASE_STRICTNESS_RANK[left.lease_strictness]
        >= LEASE_STRICTNESS_RANK[right.lease_strictness]
    )


def requirement_join(
    left: AssuranceRequirement,
    right: AssuranceRequirement,
) -> AssuranceRequirement:
    """Return the least upper bound of two requirements."""

    return AssuranceRequirement(
        key_establishment_threats=frozenset(
            left.key_establishment_threats | right.key_establishment_threats
        ),
        endpoint_authentication_threats=frozenset(
            left.endpoint_authentication_threats | right.endpoint_authentication_threats
        ),
        contract_evidence_threats=frozenset(
            left.contract_evidence_threats | right.contract_evidence_threats
        ),
        fallback_rule=left.fallback_rule
        if FALLBACK_RULE_RANK[left.fallback_rule] >= FALLBACK_RULE_RANK[right.fallback_rule]
        else right.fallback_rule,
        resumption_rule=left.resumption_rule
        if RESUMPTION_RULE_RANK[left.resumption_rule]
        >= RESUMPTION_RULE_RANK[right.resumption_rule]
        else right.resumption_rule,
        lease_strictness=left.lease_strictness
        if LEASE_STRICTNESS_RANK[left.lease_strictness]
        >= LEASE_STRICTNESS_RANK[right.lease_strictness]
        else right.lease_strictness,
    )
