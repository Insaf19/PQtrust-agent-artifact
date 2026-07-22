#!/usr/bin/env python3
"""Validate deterministic policy-stage configurations."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import z3

from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.compilation import COMPILER_IMPLEMENTATION_VERSION
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario
from pqtrust_agent.policy.validation import validate_mapper_monotonicity


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _decision_categories(result: Any) -> dict[str, list[str]]:
    return {
        decision.profile_id: [category.value for category in decision.violated_categories]
        for decision in result.profile_decisions
    }


def _validate_side(
    catalog: Any,
    agents_dir: Path,
    policies_dir: Path,
    agent_id: str,
    policy_id: str,
    task: Any,
    evaluation_time: datetime,
    monotonicity_cache: dict[Path, list[str]],
) -> Any:
    manifest = load_agent_manifest(agents_dir / f"{agent_id.replace('-', '_')}.yaml")
    policy_path = policies_dir / f"{agent_id.replace('-', '_')}.yaml"
    policy = load_agent_policy(policy_path)
    if policy.policy_id != policy_id:
        raise ValueError(f"{agent_id}: expected policy_id {policy_id}, got {policy.policy_id}")
    if policy_path not in monotonicity_cache:
        monotonicity_cache[policy_path] = validate_mapper_monotonicity(policy)
    monotonicity_errors = monotonicity_cache[policy_path]
    if monotonicity_errors:
        raise ValueError("; ".join(monotonicity_errors))
    return compile_local_policy(catalog, manifest, policy, task, evaluation_time)


def validate_policy_stage(
    catalog_path: Path,
    agents_dir: Path,
    policies_dir: Path,
    scenarios_dir: Path,
) -> dict[str, object]:
    """Return a machine-readable policy-stage validation report."""

    errors: list[str] = []
    entries: list[dict[str, object]] = []
    catalog_hash: str | None = None
    scenarios = sorted(scenarios_dir.glob("*.yaml"))
    monotonicity_cache: dict[Path, list[str]] = {}
    try:
        catalog = load_profile_catalog(catalog_path)
        catalog_hash = catalog.catalog_hash()
    except Exception as exc:
        return {
            "report_timestamp_utc": _timestamp(),
            "compiler_implementation_version": COMPILER_IMPLEMENTATION_VERSION,
            "z3_version": z3.get_version_string(),
            "catalog_hash": None,
            "scenario_count": 0,
            "scenarios": [],
            "validation_errors": [f"catalog load failed: {exc}"],
            "validation_passed": False,
        }

    for scenario_path in scenarios:
        try:
            scenario = load_scenario(scenario_path)
            initiator = _validate_side(
                catalog,
                agents_dir,
                policies_dir,
                scenario.initiator_agent_id,
                scenario.initiator_policy_id,
                scenario.task,
                scenario.evaluation_time_utc,
                monotonicity_cache,
            )
            responder = _validate_side(
                catalog,
                agents_dir,
                policies_dir,
                scenario.responder_agent_id,
                scenario.responder_policy_id,
                scenario.task,
                scenario.evaluation_time_utc,
                monotonicity_cache,
            )
            common = tuple(
                profile_id
                for profile_id in catalog.profile_ids()
                if profile_id in initiator.safe_profile_ids
                and profile_id in responder.safe_profile_ids
            )
            if not initiator.safe_profile_ids:
                errors.append(f"{scenario.scenario_id}: initiator safe set is empty")
            if not responder.safe_profile_ids:
                errors.append(f"{scenario.scenario_id}: responder safe set is empty")
            if not common:
                errors.append(f"{scenario.scenario_id}: common safe-set sanity check is empty")
            entries.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "scenario_hash": scenario.scenario_hash(),
                    "task_hash": scenario.task.context_hash(),
                    "initiator_agent_id": scenario.initiator_agent_id,
                    "responder_agent_id": scenario.responder_agent_id,
                    "initiator_safe_set": list(initiator.safe_profile_ids),
                    "responder_safe_set": list(responder.safe_profile_ids),
                    "common_safe_set_sanity_check": list(common),
                    "initiator_policy_hash": initiator.policy_hash,
                    "responder_policy_hash": responder.policy_hash,
                    "initiator_matched_rules": list(
                        initiator.requirement_derivation.matched_rule_ids
                    ),
                    "responder_matched_rules": list(
                        responder.requirement_derivation.matched_rule_ids
                    ),
                    "initiator_rejection_categories_by_profile": _decision_categories(initiator),
                    "responder_rejection_categories_by_profile": _decision_categories(responder),
                    "initiator_compilation_hash": initiator.compilation_hash,
                    "responder_compilation_hash": responder.compilation_hash,
                    "z3_version": z3.get_version_string(),
                }
            )
        except Exception as exc:
            errors.append(f"{scenario_path}: {exc}")

    return {
        "report_timestamp_utc": _timestamp(),
        "compiler_implementation_version": COMPILER_IMPLEMENTATION_VERSION,
        "z3_version": z3.get_version_string(),
        "catalog_hash": catalog_hash,
        "scenario_count": len(scenarios),
        "scenarios": entries,
        "validation_errors": errors,
        "validation_passed": not errors,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("configs/profiles/trust_profiles.yaml"),
    )
    parser.add_argument("--agents-dir", type=Path, default=Path("configs/agents"))
    parser.add_argument("--policies-dir", type=Path, default=Path("configs/policies"))
    parser.add_argument("--scenarios-dir", type=Path, default=Path("configs/scenarios"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/policy/policy_stage_validation.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = validate_policy_stage(
        args.catalog,
        args.agents_dir,
        args.policies_dir,
        args.scenarios_dir,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["validation_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
