#!/usr/bin/env python3
"""Validate Stage 5 commit-reveal transcript binding with laboratory fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from pqtrust_agent.evidence.decimal_json import dumps_decimal_json
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.preference import load_agent_cost_preference
from pqtrust_agent.models.protocol import NegotiationProposal, NegotiationReveal
from pqtrust_agent.models.selection import SELECTOR_IMPLEMENTATION_VERSION
from pqtrust_agent.negotiation.cost_evidence import load_selector_cost_evidence
from pqtrust_agent.negotiation.selector import run_bilateral_selector
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario
from pqtrust_agent.protocol.commitment import CommitRevealSession, create_commitment
from pqtrust_agent.protocol.replay import InMemoryReplayRegistry
from pqtrust_agent.protocol.transcript import build_transcript, verify_transcript

SCENARIOS = (
    "low-risk-public-tool",
    "sensitive-enterprise-api",
    "critical-edge-command",
    "low-risk-quantum-ready-tool",
)


def _agent_file(agent_id: str) -> str:
    return f"{agent_id.replace('-', '_')}.yaml"


def _fixture_hex(label: str) -> str:
    return hashlib.sha256(f"PQTrust laboratory fixture:{label}".encode()).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(dumps_decimal_json(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/protocol"))
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("configs/profiles/trust_profiles.yaml"),
    )
    parser.add_argument("--agents-dir", type=Path, default=Path("configs/agents"))
    parser.add_argument("--policies-dir", type=Path, default=Path("configs/policies"))
    parser.add_argument("--preferences-dir", type=Path, default=Path("configs/preferences"))
    parser.add_argument("--scenarios-dir", type=Path, default=Path("configs/scenarios"))
    parser.add_argument(
        "--cost-evidence-dir",
        type=Path,
        default=Path("artifacts/paired-cost-calibration/r2-vs-confirmatory"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    catalog = load_profile_catalog(args.catalog)
    catalog_hash = catalog.catalog_hash()
    cost_evidence = load_selector_cost_evidence(args.cost_evidence_dir, catalog)
    registry = InMemoryReplayRegistry()
    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    for scenario_id in SCENARIOS:
        try:
            scenario = load_scenario(args.scenarios_dir / f"{scenario_id.replace('-', '_')}.yaml")
            evaluation_time = scenario.evaluation_time_utc
            init_manifest = load_agent_manifest(
                args.agents_dir / _agent_file(scenario.initiator_agent_id)
            )
            resp_manifest = load_agent_manifest(
                args.agents_dir / _agent_file(scenario.responder_agent_id)
            )
            init_policy = load_agent_policy(
                args.policies_dir / _agent_file(scenario.initiator_agent_id)
            )
            resp_policy = load_agent_policy(
                args.policies_dir / _agent_file(scenario.responder_agent_id)
            )
            init_comp = compile_local_policy(
                catalog,
                init_manifest,
                init_policy,
                scenario.task,
                evaluation_time,
            )
            resp_comp = compile_local_policy(
                catalog,
                resp_manifest,
                resp_policy,
                scenario.task,
                evaluation_time,
            )
            init_pref = load_agent_cost_preference(
                args.preferences_dir / _agent_file(scenario.initiator_agent_id)
            )
            resp_pref = load_agent_cost_preference(
                args.preferences_dir / _agent_file(scenario.responder_agent_id)
            )
            selection = run_bilateral_selector(
                scenario=scenario,
                catalog_profile_ids=catalog.profile_ids(),
                catalog_hash=catalog_hash,
                initiator_compilation=init_comp,
                responder_compilation=resp_comp,
                initiator_preference=init_pref,
                responder_preference=resp_pref,
                cost_evidence=cost_evidence,
            )
            session_id = _fixture_hex(f"{scenario_id}:session")
            init_reveal = NegotiationReveal(
                proposal=NegotiationProposal(
                    session_id=session_id,
                    agent_id=scenario.initiator_agent_id,
                    agent_role="initiator",
                    scenario_hash=scenario.scenario_hash(),
                    task_hash=scenario.task.context_hash(),
                    catalog_hash=catalog_hash,
                    manifest_hash=init_manifest.manifest_hash(),
                    policy_compilation_hash=init_comp.compilation_hash,
                    preference_hash=init_pref.preference_hash(),
                    cost_evidence_hash=cost_evidence.evidence_hash,
                    selector_implementation_version=SELECTOR_IMPLEMENTATION_VERSION,
                    local_safe_profile_ids=init_comp.safe_profile_ids,
                    evaluation_time=evaluation_time,
                    expires_at=evaluation_time + timedelta(hours=1),
                ),
                nonce_hex=_fixture_hex(f"{scenario_id}:initiator:nonce"),
            )
            resp_reveal = init_reveal.model_copy(
                update={
                    "proposal": init_reveal.proposal.model_copy(
                        update={
                            "agent_id": scenario.responder_agent_id,
                            "agent_role": "responder",
                            "manifest_hash": resp_manifest.manifest_hash(),
                            "policy_compilation_hash": resp_comp.compilation_hash,
                            "preference_hash": resp_pref.preference_hash(),
                            "local_safe_profile_ids": resp_comp.safe_profile_ids,
                        }
                    ),
                    "nonce_hex": _fixture_hex(f"{scenario_id}:responder:nonce"),
                }
            )
            session = CommitRevealSession(
                session_id=session_id,
                activation_time=evaluation_time,
                replay_registry=registry,
            )
            session.register_commitment("initiator", create_commitment(init_reveal))
            session.register_commitment("responder", create_commitment(resp_reveal))
            session.accept_reveal(init_reveal, verification_time=evaluation_time)
            session.accept_reveal(resp_reveal, verification_time=evaluation_time)
            transcript = build_transcript(
                initiator_reveal=init_reveal,
                responder_reveal=resp_reveal,
                selection_result=selection,
                catalog_profile_ids=catalog.profile_ids(),
                created_at=evaluation_time,
            )
            verify_transcript(
                transcript,
                selection_result=selection,
                catalog_profile_ids=catalog.profile_ids(),
                verification_time=evaluation_time,
            )
            reports.append(transcript.model_dump(mode="json"))
        except Exception as exc:
            errors.append(f"{scenario_id}: {exc}")
    payload = {
        "artifact": "commit_reveal_validation",
        "laboratory_fixtures": (
            "session IDs and nonces are deterministic validation fixtures, "
            "not production randomness"
        ),
        "scenario_count": len(reports),
        "transcripts": reports,
        "validation_errors": errors,
        "validation_passed": not errors and len(reports) == len(SCENARIOS),
    }
    _write_json(args.output_dir / "commit_reveal_validation.json", payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
