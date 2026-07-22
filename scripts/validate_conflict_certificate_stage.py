"""Generate Stage 6 minimal conflict certificate validation artifacts."""

from __future__ import annotations

import argparse
import hashlib
from datetime import timedelta
from pathlib import Path
from typing import Any

from pqtrust_agent.evidence.canonical import (
    canonicalize,
    to_json_compatible,
)
from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.models.protocol import NegotiationProposal, NegotiationReveal
from pqtrust_agent.models.stage6_reports import (
    ConflictScenarioValidation,
    ConflictStageValidationReport,
    Stage6ScenarioDiagnostics,
)
from pqtrust_agent.negotiation.conflict_certificate import build_minimal_conflict_certificate
from pqtrust_agent.negotiation.conflict_constraints import satisfiable_profile_ids
from pqtrust_agent.negotiation.remediation import build_remediation_report
from pqtrust_agent.negotiation.stage6_scenarios import (
    INFEASIBLE_SCENARIO_IDS,
    NOW,
    PROFILES,
    Stage6ConflictScenario,
    constraints_for_scenario,
    registered_infeasible_scenarios,
    session_id,
    stable_hash,
    task_hash,
)
from pqtrust_agent.protocol.conflict_verification import verify_conflict_certificate

__all__ = [
    "INFEASIBLE_SCENARIO_IDS",
    "NOW",
    "PROFILES",
    "_constraints_for_scenario",
    "_hash",
    "_proposal",
    "_scenarios",
    "_session_id",
    "_write_checksums",
    "_write_json",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/conflicts-component/conflict-certificates"),
    )
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args()
    with staged_report_dir(args.output_dir, replace_existing=args.replace_existing) as out:
        _write_conflict_artifacts(out)


def _write_conflict_artifacts(out: Path, *, write_checksums: bool = True) -> None:
    (out / "certificates").mkdir()
    (out / "remediation_reports").mkdir()
    summaries: list[ConflictScenarioValidation] = []
    validation_errors: list[str] = []
    for scenario in _scenarios():
        name = scenario.name
        init_safe = scenario.initiator_safe
        resp_safe = scenario.responder_safe
        session = session_id(name)
        constraints = constraints_for_scenario(scenario)
        cert, _ = build_minimal_conflict_certificate(
            session_id=session,
            initiator_agent_id="initiator",
            responder_agent_id="responder",
            scenario_hash=stable_hash(name),
            task_hash=task_hash(name),
            catalog_hash=stable_hash("catalog"),
            initiator_manifest_hash=stable_hash(f"{name}-init-manifest"),
            responder_manifest_hash=stable_hash(f"{name}-resp-manifest"),
            initiator_policy_compilation_hash=stable_hash(f"{name}-init-policy"),
            responder_policy_compilation_hash=stable_hash(f"{name}-resp-policy"),
            commit_reveal_transcript_hash=stable_hash(f"{name}-commit-reveal"),
            candidate_profile_universe=PROFILES,
            initiator_local_safe_set=init_safe,
            responder_local_safe_set=resp_safe,
            constraints=constraints,
            issued_at=NOW,
        )
        result = verify_conflict_certificate(cert, all_constraints=constraints)
        remediation = build_remediation_report(cert)
        _write_json(out / "certificates" / f"{name}.json", cert)
        _write_json(out / "remediation_reports" / f"{name}.json", remediation)
        if not result.valid:
            validation_errors.extend(f"{name}:{error.code}" for error in result.errors)
        summaries.append(
            ConflictScenarioValidation(
                scenario_id=name,
                certificate_hash=cert.verification_hash,
                category=cert.conflict_category,
                IUS_size=cert.IUS_size,
                verification_passed=result.valid,
                validation_errors=tuple(error.code for error in result.errors),
                diagnostics=_diagnostics_for_scenario(scenario, cert.conflict_constraints),
            )
        )
    report = ConflictStageValidationReport(
        artifact="conflict_stage_validation",
        scenario_count=len(summaries),
        scenarios=tuple(summaries),
        validation_errors=tuple(validation_errors),
        validation_passed=not validation_errors and len(summaries) == len(INFEASIBLE_SCENARIO_IDS),
    )
    _write_json(out / "conflict_stage_validation.json", report)
    if write_checksums:
        _write_checksums(out)

def _diagnostics_for_scenario(
    scenario: Stage6ConflictScenario, ius: tuple[Any, ...]
) -> Stage6ScenarioDiagnostics:
    return Stage6ScenarioDiagnostics(
        capability_intersection_before_policy=scenario.capability_intersection_before_policy,
        candidate_set_after_assurance_floor=scenario.candidate_set_after_assurance_floor,
        final_common_safe_set=satisfiable_profile_ids(
            profile_ids=PROFILES, constraints=constraints_for_scenario(scenario)
        ),
        ius_categories=tuple(sorted({constraint.category for constraint in ius})),
        task_minimum_lease_seconds=scenario.task_minimum_lease_seconds,
        agent_profile_maximum_lease_seconds=scenario.agent_profile_maximum_lease_seconds,
        otherwise_compatible_candidate_profiles=scenario.otherwise_compatible_candidate_profiles,
    )


def _scenarios() -> list[Stage6ConflictScenario]:
    return list(registered_infeasible_scenarios())


def _constraints_for_scenario(scenario: Stage6ConflictScenario) -> tuple[Any, ...]:
    return constraints_for_scenario(scenario)


def _session_id(name: str) -> str:
    return session_id(name)


def _proposal(session_id: str, role: str, safe: tuple[str, ...]) -> NegotiationReveal:
    proposal = NegotiationProposal(
        session_id=session_id,
        agent_id="initiator" if role == "initiator" else "responder",
        agent_role=role,  # type: ignore[arg-type]
        scenario_hash=stable_hash("script"),
        task_hash=stable_hash("task"),
        catalog_hash=stable_hash("catalog"),
        manifest_hash=stable_hash(f"{role}-manifest"),
        policy_compilation_hash=stable_hash(f"{role}-policy"),
        preference_hash=stable_hash(f"{role}-preference"),
        cost_evidence_hash=stable_hash("cost"),
        selector_implementation_version="0.4.0",
        local_safe_profile_ids=safe,
        evaluation_time=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    return NegotiationReveal(
        proposal=proposal, nonce_hex=stable_hash(f"{session_id}-{role}")[:64]
    )


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(canonicalize(to_json_compatible(value)) + b"\n")


def _write_checksums(out: Path) -> None:
    rows = []
    for path in sorted(item for item in out.rglob("*.json")):
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out)}")
    (out / "checksums.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
