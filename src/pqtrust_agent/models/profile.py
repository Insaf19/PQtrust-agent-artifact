"""Trust profile and resource models."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.models.common import (
    AssuranceVector,
    ContractEvidenceMode,
    EndpointAuthenticationMode,
    FallbackRule,
    LeaseStrictness,
    ResourceEnvelope,
    ResumptionRule,
)
from pqtrust_agent.tls_groups import require_registered_canonical_tls_group

PROFILE_ID_RE = r"^P[0-9]+$"
TLS_GROUP_RE = r"^[A-Za-z0-9._-]+$"
EMPIRICAL_DESCRIPTION_RE = re.compile(
    r"\b(measured|benchmark|benchmarked|latency|throughput|faster|slower|"
    r"performance|experimentally|empirical|cpu time|energy use)\b",
    re.IGNORECASE,
)


class TrustProfile(BaseModel):
    """A named trust profile with explicit assurance vector and policy fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    profile_id: Annotated[str, Field(pattern=PROFILE_ID_RE)] = Field(
        description="Profile identifier."
    )
    tls_group: Annotated[str, Field(min_length=1, pattern=TLS_GROUP_RE)] = Field(
        description="OpenSSL TLS 1.3 group identifier."
    )
    endpoint_authentication_mode: EndpointAuthenticationMode = Field(
        description="Endpoint TLS authentication mode."
    )
    contract_evidence_mode: ContractEvidenceMode = Field(
        description="Application-level contract evidence mode."
    )
    fallback_rule: FallbackRule = Field(description="Declared fallback rule.")
    resumption_rule: ResumptionRule = Field(description="Declared resumption rule.")
    lease_strictness: LeaseStrictness = Field(description="Declared lease strictness.")
    max_lease_seconds: Annotated[int, Field(gt=0, strict=True)] = Field(
        description="Maximum lease duration in seconds."
    )
    assurance: AssuranceVector = Field(description="Explicit assurance vector.")
    resource_envelope: ResourceEnvelope = Field(description="Optional resource envelope.")
    description: Annotated[str, Field(min_length=1, max_length=1200)] = Field(
        description="Human-readable non-empirical profile description."
    )

    @field_validator("tls_group", mode="after")
    @classmethod
    def _canonical_tls_group(cls, value: str) -> str:
        return require_registered_canonical_tls_group(value)

    @model_validator(mode="after")
    def _validate_consistency(self) -> TrustProfile:
        if self.assurance.fallback_rule != self.fallback_rule:
            raise ValueError("assurance fallback_rule must match declared fallback_rule")
        if self.assurance.resumption_rule != self.resumption_rule:
            raise ValueError("assurance resumption_rule must match declared resumption_rule")
        if self.assurance.lease_strictness != self.lease_strictness:
            raise ValueError("assurance lease_strictness must match declared lease_strictness")
        if EMPIRICAL_DESCRIPTION_RE.search(self.description) is not None:
            raise ValueError("profile descriptions must not contain empirical claims")
        return self
