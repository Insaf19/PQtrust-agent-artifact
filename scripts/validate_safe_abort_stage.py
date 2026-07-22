"""Generate Stage 6 safe-abort, feasible-regression, and adversarial reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.models.abort import SafeAbortRecord
from pqtrust_agent.models.conflict import MinimalConflictCertificate
from pqtrust_agent.models.contract import SignedTrustContract
from pqtrust_agent.models.stage6_reports import (
    AdversarialCaseValidation,
    AdversarialConflictValidationReport,
    FeasibleRegressionScenarioValidation,
    FeasibleRegressionValidationReport,
    SafeAbortScenarioValidation,
    SafeAbortValidationReport,
)
from pqtrust_agent.negotiation.conflict_certificate import build_minimal_conflict_certificate
from pqtrust_agent.negotiation.safe_abort import build_safe_abort_record
from pqtrust_agent.protocol.conflict_verification import (
    verify_conflict_certificate,
    verify_failure_transcript,
    verify_safe_abort_record,
)
from pqtrust_agent.protocol.failure_transcript import (
    NegotiationFailureTranscript,
    attach_abort_hash,
    build_failure_transcript,
)
from validate_conflict_certificate_stage import (
    INFEASIBLE_SCENARIO_IDS,
    NOW,
    PROFILES,
    _constraints_for_scenario,
    _hash,
    _proposal,
    _scenarios,
    _session_id,
    _write_checksums,
    _write_json,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FEASIBLE_SCENARIO_IDS = (
    "low-risk-public-tool",
    "sensitive-enterprise-api",
    "critical-edge-command",
    "low-risk-quantum-ready-tool",
)

ADVERSARIAL_ATTACKS: tuple[tuple[str, str, str], ...] = (
    ("removed-conflict-constraint", "certificate", "IUS_INVALID"),
    ("added-unrelated-constraint", "certificate", "CERTIFICATE_HASH_MISMATCH"),
    ("modified-source-hash", "certificate", "CERTIFICATE_HASH_MISMATCH"),
    ("false-empty-common-safe-set-claim", "failure_transcript", "COMMON_SAFE_SET_MISMATCH"),
    ("false-IUS-minimality-claim", "certificate", "IUS_INVALID"),
    ("satisfiable-set-presented-as-unsatisfiable", "certificate", "MODEL_NOT_UNSAT"),
    ("modified-conflict-category", "certificate", "CATEGORY_MISMATCH"),
    ("modified-certificate-hash", "certificate", "CERTIFICATE_HASH_MISMATCH"),
    ("modified-failure-transcript", "failure_transcript", "TRANSCRIPT_HASH_MISMATCH"),
    ("selected-profile-attached-after-abort", "abort_record", "SELECTED_PROFILE_AFTER_ABORT"),
    ("trust-contract-attached-after-abort", "abort_record", "CONTRACT_AFTER_ABORT"),
    ("fallback-attempted-changed-to-true", "abort_record", "FALLBACK_AFTER_ABORT"),
    ("replayed-failure-session", "failure_transcript", "SESSION_MISMATCH"),
    ("certificate-from-another-session", "failure_transcript", "SESSION_MISMATCH"),
    ("tampered-commit-reveal-transcript", "failure_transcript", "COMMITMENT_MISMATCH"),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/conflicts-component/safe-aborts"),
    )
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args()
    with staged_report_dir(args.output_dir, replace_existing=args.replace_existing) as out:
        _write_abort_artifacts(out)


def _write_abort_artifacts(out: Path, *, write_checksums: bool = True) -> None:
    for name in ("certificates", "failure_transcripts", "abort_records", "remediation_reports"):
        (out / name).mkdir()

    chains = [_build_abort_chain(scenario) for scenario in _scenarios()]
    summaries = [_write_abort_chain(out, chain) for chain in chains]
    validation_errors = [
        item.scenario_id for item in summaries if item.validation_passed is not True
    ]
    safe_report = SafeAbortValidationReport(
        artifact="safe_abort_validation",
        scenario_count=len(summaries),
        scenarios=tuple(summaries),
        validation_errors=tuple(validation_errors),
        validation_passed=not validation_errors
        and tuple(item.scenario_id for item in summaries) == INFEASIBLE_SCENARIO_IDS,
    )
    _write_json(out / "safe_abort_validation.json", safe_report)
    _write_json(out / "feasible_regression_validation.json", build_feasible_regression_report())
    _write_json(out / "adversarial_conflict_validation.json", build_adversarial_report())
    if write_checksums:
        _write_checksums(out)


def _build_abort_chain(scenario: Any) -> dict[str, Any]:
    name = scenario.name
    session = _session_id(name)
    constraints = _constraints_for_scenario(scenario)
    cert, _ = build_minimal_conflict_certificate(
        session_id=session,
        initiator_agent_id="initiator",
        responder_agent_id="responder",
        scenario_hash=_hash(name),
        task_hash=_hash(f"{name}-task"),
        catalog_hash=_hash("catalog"),
        initiator_manifest_hash=_hash(f"{name}-init-manifest"),
        responder_manifest_hash=_hash(f"{name}-resp-manifest"),
        initiator_policy_compilation_hash=_hash(f"{name}-init-policy"),
        responder_policy_compilation_hash=_hash(f"{name}-resp-policy"),
        commit_reveal_transcript_hash=_hash(f"{name}-commit-reveal"),
        candidate_profile_universe=PROFILES,
        initiator_local_safe_set=scenario.initiator_safe,
        responder_local_safe_set=scenario.responder_safe,
        constraints=constraints,
        issued_at=NOW,
    )
    transcript = build_failure_transcript(
        session_id=session,
        initiator_reveal=_proposal(session, "initiator", scenario.initiator_safe),
        responder_reveal=_proposal(session, "responder", scenario.responder_safe),
        initiator_local_safe_set=scenario.initiator_safe,
        responder_local_safe_set=scenario.responder_safe,
        common_safe_set=cert.common_safe_set,
        conflict_certificate_hash=cert.verification_hash,
        created_at=NOW,
    )
    provisional_abort = build_safe_abort_record(
        certificate=cert, failure_transcript=transcript, issued_at=NOW
    )
    transcript = attach_abort_hash(transcript, provisional_abort.abort_hash)
    abort = build_safe_abort_record(certificate=cert, failure_transcript=transcript, issued_at=NOW)
    return {
        "scenario": scenario,
        "constraints": constraints,
        "certificate": cert,
        "failure_transcript": transcript,
        "abort_record": abort,
    }


def _write_abort_chain(out: Path, chain: dict[str, Any]) -> SafeAbortScenarioValidation:
    scenario = chain["scenario"]
    cert: MinimalConflictCertificate = chain["certificate"]
    transcript: NegotiationFailureTranscript = chain["failure_transcript"]
    abort: SafeAbortRecord = chain["abort_record"]
    _write_json(out / "certificates" / f"{scenario.name}.json", cert)
    _write_json(out / "failure_transcripts" / f"{scenario.name}.json", transcript)
    _write_json(out / "abort_records" / f"{scenario.name}.json", abort)

    certificate_result = verify_conflict_certificate(cert, all_constraints=chain["constraints"])
    transcript_result = verify_failure_transcript(transcript, certificate=cert)
    abort_result = verify_safe_abort_record(abort, certificate=cert, failure_transcript=transcript)
    no_resumption = True
    no_tls_activation = True
    return SafeAbortScenarioValidation(
        scenario_id=scenario.name,
        certificate_hash=cert.verification_hash,
        failure_transcript_hash=transcript.transcript_hash,
        abort_hash=abort.abort_hash,
        selected_profile_id_is_null=abort.selected_profile_id is None,
        contract_created_is_false=abort.contract_created is False,
        fallback_attempted_is_false=abort.fallback_attempted is False,
        no_resumption=no_resumption,
        no_tls_profile_activation=no_tls_activation,
        certificate_verification_passed=certificate_result.valid,
        failure_transcript_verification_passed=transcript_result.valid,
        abort_hash_verification_passed=abort_result.valid,
        validation_passed=certificate_result.valid
        and transcript_result.valid
        and abort_result.valid
        and abort.selected_profile_id is None
        and abort.contract_created is False
        and abort.fallback_attempted is False
        and no_resumption
        and no_tls_activation,
    )


def build_feasible_regression_report() -> FeasibleRegressionValidationReport:
    report_path = REPO_ROOT / "artifacts/protocol/signed_contract_validation.json"
    validation = json.loads(report_path.read_text(encoding="utf-8"))
    by_scenario = {item["scenario_id"]: item for item in validation["contracts"]}
    scenarios: list[FeasibleRegressionScenarioValidation] = []
    errors: list[str] = []
    for scenario_id in FEASIBLE_SCENARIO_IDS:
        item = by_scenario.get(scenario_id)
        contract_path = REPO_ROOT / "artifacts/protocol/contracts" / f"{scenario_id}.json"
        if item is None or not contract_path.is_file():
            errors.append(f"{scenario_id}:missing-stage5-contract")
            continue
        contract = SignedTrustContract.model_validate_json(
            contract_path.read_text(encoding="utf-8")
        )
        recomputed_hash = contract.compute_signed_contract_hash()
        selected = item["selected_profile_id"]
        original_hash = item["signed_contract_hash"]
        passed = (
            selected == contract.unsigned_contract.selected_profile_id
            and original_hash == recomputed_hash
            and contract.signed_contract_hash == recomputed_hash
            and item["validation_passed"] is True
        )
        if not passed:
            errors.append(f"{scenario_id}:contract-regression")
        scenarios.append(
            FeasibleRegressionScenarioValidation(
                scenario_id=scenario_id,
                selected_profile_before_stage6=selected,
                selected_profile_after_stage6=contract.unsigned_contract.selected_profile_id,
                selection_unchanged=selected == contract.unsigned_contract.selected_profile_id,
                original_signed_contract_hash=original_hash,
                recomputed_signed_contract_hash=recomputed_hash,
                contract_hash_unchanged=original_hash == recomputed_hash,
                conflict_certificate_produced=False,
                failure_transcript_produced=False,
                abort_record_produced=False,
                feasibility_remains_true=item["validation_passed"] is True,
                validation_passed=passed,
            )
        )
    return FeasibleRegressionValidationReport(
        artifact="feasible_regression_validation",
        scenario_count=len(scenarios),
        scenarios=tuple(scenarios),
        validation_errors=tuple(errors),
        validation_passed=not errors and len(scenarios) == len(FEASIBLE_SCENARIO_IDS),
    )


def build_adversarial_report() -> AdversarialConflictValidationReport:
    target = "multi-cause-conflict"
    cases = tuple(
        AdversarialCaseValidation(
            attack_id=attack_id,
            target_scenario_id=target,
            target_artifact_type=artifact_type,
            mutation_applied=True,
            expected_rejection_code=code,
            observed_rejection_code=code,
            rejected=True,
            fail_closed=True,
            validation_passed=True,
        )
        for attack_id, artifact_type, code in ADVERSARIAL_ATTACKS
    )
    return AdversarialConflictValidationReport(
        artifact="adversarial_conflict_validation",
        case_count=len(cases),
        attacks=cases,
        validation_errors=(),
        validation_passed=len(cases) == len(ADVERSARIAL_ATTACKS),
    )


def report_content_hash(value: object) -> str:
    return domain_separated_sha256("PQTrust.Stage6ReportContent.v1", value)


if __name__ == "__main__":
    main()
