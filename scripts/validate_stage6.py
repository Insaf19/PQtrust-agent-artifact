#!/usr/bin/env python3
"""Generate the complete Stage 6 artifact bundle atomically."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from pqtrust_agent.evidence.canonical import canonicalize, to_json_compatible
from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.models.abort import SafeAbortRecord
from pqtrust_agent.models.conflict import MinimalConflictCertificate
from pqtrust_agent.models.stage6_reports import (
    AdversarialConflictValidationReport,
    ConflictStageValidationReport,
    FeasibleRegressionValidationReport,
    SafeAbortValidationReport,
    Stage6BundleValidationReport,
)
from pqtrust_agent.negotiation.conflict_certificate import classify_conflict
from pqtrust_agent.protocol.conflict_verification import (
    verify_failure_transcript,
    verify_safe_abort_record,
)
from pqtrust_agent.protocol.failure_transcript import NegotiationFailureTranscript
from validate_conflict_certificate_stage import (
    INFEASIBLE_SCENARIO_IDS,
    _write_conflict_artifacts,
    _write_json,
)
from validate_safe_abort_stage import (
    ADVERSARIAL_ATTACKS,
    FEASIBLE_SCENARIO_IDS,
    _write_abort_artifacts,
)

OUTPUT_DIR = Path("artifacts/conflicts")
BUNDLE_REPORT = "stage6_bundle_validation.json"
CHECKSUMS = "checksums.sha256"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args()
    validate_stage6(args.output_dir, replace_existing=args.replace_existing)


def validate_stage6(output_dir: Path, *, replace_existing: bool) -> dict[str, Any]:
    """Build and atomically publish the complete Stage 6 artifact bundle."""

    with staged_report_dir(output_dir, replace_existing=replace_existing) as out:
        report = build_stage6_bundle(out)
    return report


def build_stage6_bundle(out: Path) -> dict[str, Any]:
    """Build a complete Stage 6 bundle in an already-empty staging directory."""

    components = out / ".components"
    conflict_component = components / "conflict-certificates"
    abort_component = components / "safe-aborts"
    conflict_component.mkdir(parents=True)
    abort_component.mkdir(parents=True)

    _write_conflict_artifacts(conflict_component, write_checksums=False)
    _write_abort_artifacts(abort_component, write_checksums=False)

    _copy_file(conflict_component / "conflict_stage_validation.json", out)
    for name in (
        "safe_abort_validation.json",
        "feasible_regression_validation.json",
        "adversarial_conflict_validation.json",
    ):
        _copy_file(abort_component / name, out)

    shutil.copytree(conflict_component / "certificates", out / "certificates")
    shutil.copytree(conflict_component / "remediation_reports", out / "remediation_reports")
    shutil.copytree(abort_component / "failure_transcripts", out / "failure_transcripts")
    shutil.copytree(abort_component / "abort_records", out / "abort_records")
    shutil.rmtree(components)

    report_model = _bundle_report(out, checksum_validation_passed=True)
    if not report_model.validation_passed:
        raise ValueError(f"Stage 6 semantic validation failed: {report_model.validation_errors}")
    _write_json(out / BUNDLE_REPORT, report_model)
    write_checksums(out)
    verify_checksums(out)
    return report_model.model_dump(mode="json")


def write_checksums(out: Path) -> None:
    rows = []
    for path in _regular_artifacts(out):
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out)}")
    (out / CHECKSUMS).write_text("\n".join(rows) + "\n", encoding="utf-8")


def verify_checksums(out: Path) -> None:
    checksum_path = out / CHECKSUMS
    expected = _checksum_entries(checksum_path)
    actual = {
        path.relative_to(out).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in _regular_artifacts(out)
    }
    if expected != actual:
        missing = sorted(set(actual) - set(expected))
        stale = sorted(set(expected) - set(actual))
        mismatched = sorted(
            name for name in set(expected) & set(actual) if expected[name] != actual[name]
        )
        raise ValueError(
            "checksum verification failed: "
            f"missing={missing}, stale={stale}, mismatched={mismatched}"
        )


def _bundle_report(out: Path, *, checksum_validation_passed: bool) -> Stage6BundleValidationReport:
    errors: list[str] = []
    try:
        conflict_report = ConflictStageValidationReport.model_validate(
            _read_json(out / "conflict_stage_validation.json")
        )
        safe_abort_report = SafeAbortValidationReport.model_validate(
            _read_json(out / "safe_abort_validation.json")
        )
        feasible_report = FeasibleRegressionValidationReport.model_validate(
            _read_json(out / "feasible_regression_validation.json")
        )
        adversarial_report = AdversarialConflictValidationReport.model_validate(
            _read_json(out / "adversarial_conflict_validation.json")
        )
    except Exception as exc:
        return _invalid_bundle_report(
            out,
            checksum_validation_passed=checksum_validation_passed,
            errors=(f"report-type-validation:{type(exc).__name__}",),
        )

    expected_ids = set(INFEASIBLE_SCENARIO_IDS)
    conflict_ids = [item.scenario_id for item in conflict_report.scenarios]
    safe_ids = [item.scenario_id for item in safe_abort_report.scenarios]
    feasible_ids = [item.scenario_id for item in feasible_report.scenarios]
    attack_ids = [item.attack_id for item in adversarial_report.attacks]
    for label, ids, expected in (
        ("conflict", conflict_ids, expected_ids),
        ("safe_abort", safe_ids, expected_ids),
        ("feasible", feasible_ids, set(FEASIBLE_SCENARIO_IDS)),
        ("adversarial", attack_ids, {item[0] for item in ADVERSARIAL_ATTACKS}),
    ):
        if len(ids) != len(set(ids)):
            errors.append(f"{label}:duplicate-ids")
        if set(ids) != expected:
            errors.append(f"{label}:unexpected-ids")

    counts = {
        "certificates": _count_json(out / "certificates"),
        "failure_transcripts": _count_json(out / "failure_transcripts"),
        "abort_records": _count_json(out / "abort_records"),
        "remediation_reports": _count_json(out / "remediation_reports"),
    }
    if counts["certificates"] != 5:
        errors.append("certificate-count")
    if counts["failure_transcripts"] != 5:
        errors.append("failure-transcript-count")
    if counts["abort_records"] != 5:
        errors.append("abort-record-count")
    if counts["remediation_reports"] != 5:
        errors.append("remediation-report-count")
    if safe_abort_report.scenario_count != 5:
        errors.append("safe-abort-scenario-count")
    if feasible_report.scenario_count != 4:
        errors.append("feasible-regression-scenario-count")
    if adversarial_report.case_count != 15:
        errors.append("adversarial-case-count")

    report_hashes = {
        name: _hash_report_file(out / name)
        for name in (
            "conflict_stage_validation.json",
            "safe_abort_validation.json",
            "feasible_regression_validation.json",
            "adversarial_conflict_validation.json",
        )
    }
    payload_hashes = {
        name: _hash_report_payload(out / name)
        for name in (
            "conflict_stage_validation.json",
            "safe_abort_validation.json",
            "feasible_regression_validation.json",
            "adversarial_conflict_validation.json",
        )
    }
    if len(set(payload_hashes.values())) != len(payload_hashes):
        errors.append("duplicated-report-scientific-payload")
    if _contains_key(_read_json(out / "feasible_regression_validation.json"), "abort_hash"):
        errors.append("feasible-report-contains-abort-hash")
    if "scenarios" in _read_json(out / "adversarial_conflict_validation.json"):
        errors.append("adversarial-report-reused-scenario-payload")

    taxonomy_ok = _validate_taxonomy(out, errors)
    refs_ok = _validate_cross_references(out, errors)

    all_component_passed = (
        conflict_report.validation_passed
        and safe_abort_report.validation_passed
        and feasible_report.validation_passed
        and adversarial_report.validation_passed
    )
    validation_passed = (
        all_component_passed
        and taxonomy_ok
        and refs_ok
        and checksum_validation_passed
        and not errors
    )
    return Stage6BundleValidationReport(
        artifact="stage6_bundle_validation",
        expected_infeasible_scenario_count=len(INFEASIBLE_SCENARIO_IDS),
        generated_certificate_count=counts["certificates"],
        generated_failure_transcript_count=counts["failure_transcripts"],
        generated_abort_record_count=counts["abort_records"],
        generated_remediation_report_count=counts["remediation_reports"],
        safe_abort_scenario_count=safe_abort_report.scenario_count,
        feasible_regression_scenario_count=feasible_report.scenario_count,
        adversarial_case_count=adversarial_report.case_count,
        conflict_validation_passed=conflict_report.validation_passed,
        safe_abort_validation_passed=safe_abort_report.validation_passed,
        feasible_regression_passed=feasible_report.validation_passed,
        adversarial_validation_passed=adversarial_report.validation_passed,
        taxonomy_validation_passed=taxonomy_ok,
        cross_artifact_reference_validation_passed=refs_ok,
        checksum_validation_passed=checksum_validation_passed,
        report_content_hashes=report_hashes,
        validation_errors=tuple(errors),
        validation_passed=validation_passed,
    )


def _invalid_bundle_report(
    out: Path, *, checksum_validation_passed: bool, errors: tuple[str, ...]
) -> Stage6BundleValidationReport:
    report_names = (
        "conflict_stage_validation.json",
        "safe_abort_validation.json",
        "feasible_regression_validation.json",
        "adversarial_conflict_validation.json",
    )
    return Stage6BundleValidationReport(
        artifact="stage6_bundle_validation",
        expected_infeasible_scenario_count=len(INFEASIBLE_SCENARIO_IDS),
        generated_certificate_count=_count_json(out / "certificates"),
        generated_failure_transcript_count=_count_json(out / "failure_transcripts"),
        generated_abort_record_count=_count_json(out / "abort_records"),
        generated_remediation_report_count=_count_json(out / "remediation_reports"),
        safe_abort_scenario_count=0,
        feasible_regression_scenario_count=0,
        adversarial_case_count=0,
        conflict_validation_passed=False,
        safe_abort_validation_passed=False,
        feasible_regression_passed=False,
        adversarial_validation_passed=False,
        taxonomy_validation_passed=False,
        cross_artifact_reference_validation_passed=False,
        checksum_validation_passed=checksum_validation_passed,
        report_content_hashes={
            name: _hash_report_file(out / name)
            for name in report_names
            if (out / name).is_file()
        },
        validation_errors=errors,
        validation_passed=False,
    )


def _validate_taxonomy(out: Path, errors: list[str]) -> bool:
    ok = True
    for scenario_id in INFEASIBLE_SCENARIO_IDS:
        cert = MinimalConflictCertificate.model_validate(
            _read_json(out / "certificates" / f"{scenario_id}.json")
        )
        expected = classify_conflict(cert.conflict_constraints)
        if cert.conflict_category != expected:
            errors.append(f"{scenario_id}:taxonomy-mismatch")
            ok = False
    return ok


def _validate_cross_references(out: Path, errors: list[str]) -> bool:
    ok = True
    for scenario_id in INFEASIBLE_SCENARIO_IDS:
        paths = (
            out / "certificates" / f"{scenario_id}.json",
            out / "failure_transcripts" / f"{scenario_id}.json",
            out / "abort_records" / f"{scenario_id}.json",
        )
        if not all(path.is_file() for path in paths):
            errors.append(f"{scenario_id}:missing-artifact-chain")
            ok = False
            continue
        cert = MinimalConflictCertificate.model_validate(_read_json(paths[0]))
        transcript = NegotiationFailureTranscript.model_validate(_read_json(paths[1]))
        abort = SafeAbortRecord.model_validate(_read_json(paths[2]))
        transcript_result = verify_failure_transcript(transcript, certificate=cert)
        abort_result = verify_safe_abort_record(
            abort, certificate=cert, failure_transcript=transcript
        )
        same_session = cert.session_id == transcript.session_id == abort.session_id
        if not transcript_result.valid or not abort_result.valid or not same_session:
            errors.append(f"{scenario_id}:cross-artifact-reference")
            ok = False
    return ok


def _regular_artifacts(out: Path) -> list[Path]:
    return sorted(
        path
        for path in out.rglob("*")
        if path.is_file() and path.name != CHECKSUMS and ".components" not in path.parts
    )


def _checksum_entries(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, relative_path = line.split("  ", 1)
        entries[relative_path] = digest
    return entries


def _copy_file(source: Path, out: Path) -> None:
    shutil.copy2(source, out / source.name)


def _count_json(path: Path) -> int:
    return len(list(path.glob("*.json")))


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _hash_report_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_report_payload(path: Path) -> str:
    payload = _read_json(path)
    for key in ("artifact", "report_version"):
        payload.pop(key, None)
    return hashlib.sha256(canonicalize(to_json_compatible(payload))).hexdigest()


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


if __name__ == "__main__":
    main()
