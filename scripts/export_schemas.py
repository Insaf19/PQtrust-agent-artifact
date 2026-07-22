#!/usr/bin/env python3
"""Export deterministic JSON Schemas for PQTrust-Agent protocol models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import TypeAdapter

from pqtrust_agent.models import (
    AgentPolicy,
    AssuranceRequirement,
    AssuranceVector,
    CapabilityManifestPayload,
    PolicyCompilationResult,
    PolicyRule,
    ProfileCatalog,
    ProfileCompilationDecision,
    RequirementContribution,
    RequirementDerivation,
    ResourceEnvelope,
    ScenarioDefinition,
    TaskDescriptor,
    TaskRuleCondition,
    TrustProfile,
)

SCHEMAS = (
    ("task_descriptor.schema.json", TaskDescriptor),
    ("assurance_vector.schema.json", AssuranceVector),
    ("resource_envelope.schema.json", ResourceEnvelope),
    ("trust_profile.schema.json", TrustProfile),
    ("profile_catalog.schema.json", ProfileCatalog),
    ("capability_manifest_payload.schema.json", CapabilityManifestPayload),
    ("assurance_requirement.schema.json", AssuranceRequirement),
    ("task_rule_condition.schema.json", TaskRuleCondition),
    ("requirement_contribution.schema.json", RequirementContribution),
    ("policy_rule.schema.json", PolicyRule),
    ("agent_policy.schema.json", AgentPolicy),
    ("requirement_derivation.schema.json", RequirementDerivation),
    ("scenario_definition.schema.json", ScenarioDefinition),
    ("profile_compilation_decision.schema.json", ProfileCompilationDecision),
    ("policy_compilation_result.schema.json", PolicyCompilationResult),
)


def export_schemas(output_dir: Path) -> None:
    """Write all configured schemas to ``output_dir``."""

    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, model in SCHEMAS:
        schema = TypeAdapter(model).json_schema()
        (output_dir / filename).write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("schemas"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    export_schemas(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
