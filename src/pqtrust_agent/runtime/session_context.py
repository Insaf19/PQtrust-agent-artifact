"""Stage 7 session context."""

from __future__ import annotations

from dataclasses import dataclass

from pqtrust_agent.models.contract import SignedTrustContract
from pqtrust_agent.models.protocol import NegotiationTranscript
from pqtrust_agent.models.runtime import DiscoveryResult
from pqtrust_agent.models.selection import BilateralSelectionResult
from pqtrust_agent.models.transport import AuthorizedExecutionContext, TlsExecutionResult


@dataclass
class SessionContext:
    session_id: str
    scenario_id: str
    discovery: DiscoveryResult | None = None
    transcript: NegotiationTranscript | None = None
    selection_result: BilateralSelectionResult | None = None
    signed_contract: SignedTrustContract | None = None
    authorized_execution: AuthorizedExecutionContext | None = None
    tls_result: TlsExecutionResult | None = None
