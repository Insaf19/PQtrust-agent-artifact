"""YAML loaders for policy-stage configuration."""

from __future__ import annotations

from pathlib import Path

from pqtrust_agent.evidence.yaml_loader import load_yaml_model
from pqtrust_agent.models.manifest import CapabilityManifestPayload
from pqtrust_agent.models.policy import AgentPolicy
from pqtrust_agent.models.scenario import ScenarioDefinition


def load_agent_manifest(path: Path) -> CapabilityManifestPayload:
    """Load an unsigned laboratory capability manifest fixture."""

    return load_yaml_model(path, CapabilityManifestPayload)


def load_agent_policy(path: Path) -> AgentPolicy:
    """Load a private agent policy."""

    return load_yaml_model(path, AgentPolicy)


def load_scenario(path: Path) -> ScenarioDefinition:
    """Load a deterministic scenario definition."""

    return load_yaml_model(path, ScenarioDefinition)
