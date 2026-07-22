"""Shared typed model primitives for PQTrust-Agent trust contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import ConfigDict, Field, field_serializer, field_validator
from pydantic.dataclasses import dataclass


class ThreatClass(StrEnum):
    """Threat classes represented independently for each assurance dimension."""

    CLASSICAL = "classical"
    QUANTUM = "quantum"


class EndpointAuthenticationMode(StrEnum):
    """Endpoint-authentication mechanisms represented in a trust profile."""

    CLASSICAL_X509 = "classical_x509"
    DUAL_X509_MLDSA = "dual_x509_mldsa"
    PQ_MLDSA = "pq_mldsa"


class ContractEvidenceMode(StrEnum):
    """Application-level evidence mode for manifests and future contracts."""

    MLDSA65 = "mldsa65"
    MLDSA87 = "mldsa87"


class EvidenceAlgorithm(StrEnum):
    """Canonical public algorithm identifiers for contract evidence keys."""

    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


_EVIDENCE_ALGORITHM_ALIASES: dict[str, EvidenceAlgorithm] = {
    "ML-DSA-65": EvidenceAlgorithm.ML_DSA_65,
    "ML-DSA-87": EvidenceAlgorithm.ML_DSA_87,
    "MLDSA65": EvidenceAlgorithm.ML_DSA_65,
    "MLDSA87": EvidenceAlgorithm.ML_DSA_87,
    "MLDSA-65": EvidenceAlgorithm.ML_DSA_65,
    "MLDSA-87": EvidenceAlgorithm.ML_DSA_87,
    "ML-DSA65": EvidenceAlgorithm.ML_DSA_65,
    "ML-DSA87": EvidenceAlgorithm.ML_DSA_87,
    "MLZDSAZ65": EvidenceAlgorithm.ML_DSA_65,
    "MLZDSAZ87": EvidenceAlgorithm.ML_DSA_87,
}


def canonical_evidence_algorithm(value: str | EvidenceAlgorithm) -> EvidenceAlgorithm:
    """Return the canonical public evidence-algorithm identifier."""

    if isinstance(value, EvidenceAlgorithm):
        return value
    normalized = value.strip().upper().replace("_", "-")
    if normalized in _EVIDENCE_ALGORITHM_ALIASES:
        return _EVIDENCE_ALGORITHM_ALIASES[normalized]
    raise ValueError(f"unsupported evidence algorithm: {value}")


def algorithm_for_contract_evidence(mode: ContractEvidenceMode) -> EvidenceAlgorithm:
    """Map a profile contract-evidence mode to its required signing algorithm."""

    if mode == ContractEvidenceMode.MLDSA65:
        return EvidenceAlgorithm.ML_DSA_65
    if mode == ContractEvidenceMode.MLDSA87:
        return EvidenceAlgorithm.ML_DSA_87
    raise ValueError(f"unsupported contract evidence mode: {mode}")


class FallbackRule(StrEnum):
    """Fallback policy for profile selection and future negotiation."""

    LOW_RISK_ONLY = "low_risk_only"
    EXPLICIT_ONLY = "explicit_only"
    FORBIDDEN = "forbidden"


class ResumptionRule(StrEnum):
    """Session resumption binding rule."""

    CONTEXT_BOUND = "context_bound"
    CONTRACT_BOUND = "contract_bound"
    FORBIDDEN = "forbidden"


class LeaseStrictness(StrEnum):
    """Lease-duration strictness class."""

    LONG = "long"
    MEDIUM = "medium"
    SHORT = "short"


class ResourceClass(StrEnum):
    """Resource environment advertised by an agent manifest."""

    CLOUD = "cloud"
    ENTERPRISE = "enterprise"
    EDGE_CONSTRAINED = "edge_constrained"


class TaskSensitivity(StrEnum):
    """Sensitivity class of the task descriptor public context."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class OperationalImpact(StrEnum):
    """Operational impact class of the task descriptor public context."""

    OBSERVATION = "observation"
    BUSINESS_ACTION = "business_action"
    PHYSICAL_CONTROL = "physical_control"


class ConfidentialityHorizon(StrEnum):
    """Expected confidentiality horizon of task data."""

    SHORT = "short"
    MEDIUM = "medium"
    LONG = "long"


class NetworkClass(StrEnum):
    """Network environment class for the task descriptor public context."""

    STABLE_CLOUD = "stable_cloud"
    ENTERPRISE_WAN = "enterprise_wan"
    CONSTRAINED_EDGE = "constrained_edge"


TASK_SENSITIVITY_RANK: dict[TaskSensitivity, int] = {
    TaskSensitivity.PUBLIC: 0,
    TaskSensitivity.INTERNAL: 1,
    TaskSensitivity.CONFIDENTIAL: 2,
    TaskSensitivity.RESTRICTED: 3,
}

OPERATIONAL_IMPACT_RANK: dict[OperationalImpact, int] = {
    OperationalImpact.OBSERVATION: 0,
    OperationalImpact.BUSINESS_ACTION: 1,
    OperationalImpact.PHYSICAL_CONTROL: 2,
}

CONFIDENTIALITY_HORIZON_RANK: dict[ConfidentialityHorizon, int] = {
    ConfidentialityHorizon.SHORT: 0,
    ConfidentialityHorizon.MEDIUM: 1,
    ConfidentialityHorizon.LONG: 2,
}

FALLBACK_RULE_RANK: dict[FallbackRule, int] = {
    FallbackRule.LOW_RISK_ONLY: 0,
    FallbackRule.EXPLICIT_ONLY: 1,
    FallbackRule.FORBIDDEN: 2,
}

RESUMPTION_RULE_RANK: dict[ResumptionRule, int] = {
    ResumptionRule.CONTEXT_BOUND: 0,
    ResumptionRule.CONTRACT_BOUND: 1,
    ResumptionRule.FORBIDDEN: 2,
}

LEASE_STRICTNESS_RANK: dict[LeaseStrictness, int] = {
    LeaseStrictness.LONG: 0,
    LeaseStrictness.MEDIUM: 1,
    LeaseStrictness.SHORT: 2,
}

PositiveOptionalInt = Annotated[int | None, Field(default=None, gt=0, strict=True)]


@dataclass(frozen=True, config=ConfigDict(extra="forbid"))
class AssuranceVector:
    """Component-wise assurance vector used by the partial order."""

    key_establishment_threats: frozenset[ThreatClass] = Field(
        description="Threat classes addressed by key establishment."
    )
    endpoint_authentication_threats: frozenset[ThreatClass] = Field(
        description="Threat classes addressed by endpoint authentication."
    )
    contract_evidence_threats: frozenset[ThreatClass] = Field(
        description="Threat classes addressed by application-level contract evidence."
    )
    fallback_rule: FallbackRule = Field(description="Fallback policy strictness.")
    resumption_rule: ResumptionRule = Field(description="Resumption binding strictness.")
    lease_strictness: LeaseStrictness = Field(description="Lease strictness class.")

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


@dataclass(frozen=True, config=ConfigDict(extra="forbid"))
class ResourceEnvelope:
    """Optional resource limits, left null until calibrated by real measurements."""

    max_handshake_bytes: PositiveOptionalInt = Field(
        default=None,
        description="Optional positive bound on handshake bytes; null means unconstrained.",
    )
    max_peak_memory_kib: PositiveOptionalInt = Field(
        default=None,
        description="Optional positive bound on peak memory in KiB; null means unconstrained.",
    )
    max_cpu_time_microseconds: PositiveOptionalInt = Field(
        default=None,
        description="Optional positive bound on CPU time; null means unconstrained.",
    )
    max_energy_proxy_units: PositiveOptionalInt = Field(
        default=None,
        description="Optional positive bound on energy proxy units; null means unconstrained.",
    )

    def has_empirical_values(self) -> bool:
        """Return true when any resource field has a calibrated value."""

        return any(
            value is not None
            for value in (
                self.max_handshake_bytes,
                self.max_peak_memory_kib,
                self.max_cpu_time_microseconds,
                self.max_energy_proxy_units,
            )
        )
