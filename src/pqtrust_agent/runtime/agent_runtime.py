"""Local discovery registry and shared runtime helpers."""

from __future__ import annotations

from datetime import datetime

from pqtrust_agent.models.runtime import AgentAdvertisement, DiscoveryResult
from pqtrust_agent.runtime.errors import DiscoveryError


class LocalDiscoveryRegistry:
    """Deterministic laboratory discovery registry.

    Only public advertisement metadata is stored. Private policies are never accepted by
    this registry and therefore cannot be disclosed through discovery results.
    """

    def __init__(
        self,
        *,
        expected_manifest_hashes: dict[str, str],
        known_evidence_key_fingerprints: set[str],
        supported_protocol_versions: set[str] | None = None,
    ) -> None:
        self.expected_manifest_hashes = expected_manifest_hashes
        self.known_evidence_key_fingerprints = known_evidence_key_fingerprints
        self.supported_protocol_versions = supported_protocol_versions or {"1.0"}
        self._ads: dict[str, AgentAdvertisement] = {}

    def register(self, advertisement: AgentAdvertisement, *, reference_time: datetime) -> None:
        if advertisement.agent_id in self._ads:
            raise DiscoveryError("duplicate agent ID")
        if advertisement.protocol_version not in self.supported_protocol_versions:
            raise DiscoveryError("unsupported protocol version")
        if not advertisement.valid_from <= reference_time < advertisement.valid_until:
            raise DiscoveryError("expired advertisement")
        expected_hash = self.expected_manifest_hashes.get(advertisement.agent_id)
        if expected_hash is None or expected_hash != advertisement.manifest_hash:
            raise DiscoveryError("manifest-hash mismatch")
        if advertisement.evidence_key_fingerprint not in self.known_evidence_key_fingerprints:
            raise DiscoveryError("unknown evidence-key fingerprint")
        self._ads[advertisement.agent_id] = advertisement

    def discover(self, agent_ids: tuple[str, ...]) -> DiscoveryResult:
        ads: list[AgentAdvertisement] = []
        for agent_id in sorted(agent_ids):
            try:
                ads.append(self._ads[agent_id])
            except KeyError as exc:
                raise DiscoveryError(f"agent not discovered: {agent_id}") from exc
        result = DiscoveryResult(advertisements=tuple(ads), discovery_hash="0" * 64)
        return result.model_copy(update={"discovery_hash": result.compute_discovery_hash()})
