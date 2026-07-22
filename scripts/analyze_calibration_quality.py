#!/usr/bin/env python3
"""Generate Stage 3C quality diagnostics for an immutable calibration run."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.smoke_validation import atomic_write_json, write_checksums
from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.metrics.calibration_config_resolver import (
    ResolvedCalibrationConfig,
    resolve_raw_run_config_with_optional_external,
)
from pqtrust_agent.metrics.calibration_quality import (
    MLDSA_METRICS,
    MLDSA_TIMING_METRICS,
    TIMING_STABILITY_THRESHOLD,
    TLS_METRICS,
    TLS_TIMING_METRICS,
    WINDOW_SIZE_BLOCKS,
    any_warning,
    bootstrap_quality,
    group_mldsa_records,
    group_tls_records,
    machine_state_audit,
    outlier_diagnostics,
    replicate_stability,
    robust_trend,
    windowed_drift,
)
from pqtrust_agent.metrics.run_manifest import git_commit, git_dirty, utc_now
from pqtrust_agent.metrics.validation import (
    load_json,
    raw_run_checksum,
    validate_raw_run,
)

IMPLEMENTATION_VERSION = 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Optional external config to verify against the raw run's config_snapshot.yaml. "
            "When omitted, the raw-run snapshot is used."
        ),
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--raw-root", type=Path, default=Path("runs/raw/crypto_calibration"))
    parser.add_argument("--summary-root", type=Path, default=Path("artifacts/calibration"))
    parser.add_argument(
        "--artifact-root", type=Path, default=Path("artifacts/calibration-quality")
    )
    parser.add_argument("--replace-existing", action="store_true")
    return parser.parse_args()


def _load_summary(summary_root: Path, run_id: str, name: str) -> dict[str, Any]:
    path = summary_root / run_id / name
    if not path.is_file():
        raise FileNotFoundError(path)
    return load_json(path)


def _integrity_summary(
    validation: dict[str, Any],
    resolved: ResolvedCalibrationConfig,
    validation_source: str,
) -> dict[str, Any]:
    manifest = resolved.manifest
    raw_file_inventory = manifest.get("raw_file_inventory", [])
    checks = validation.get("checks", {})
    if not isinstance(checks, dict):
        checks = {}
    reasons = validation.get("not_evaluated_reasons", {})
    if not isinstance(reasons, dict):
        reasons = {}
    required = (
        "raw_checksums_valid",
        "record_counts_exact",
        "block_balance_valid",
        "every_cryptographic_operation_successful",
        "no_missing_replicates",
        "configuration_snapshot_matches_manifest",
    )
    normalized: dict[str, bool | None] = {}
    normalized_reasons: dict[str, str] = {}
    for key in required:
        value = checks.get(key)
        normalized[key] = value if value in (True, False, None) else None
        if normalized[key] is None:
            normalized_reasons[key] = str(reasons.get(key, "check was not evaluated"))
    normalized["configuration_snapshot_matches_manifest"] = (
        bool(normalized["configuration_snapshot_matches_manifest"])
        and resolved.manifest_configuration_hash_matches
    )
    integrity_passed = all(normalized[key] is True for key in required)
    return {
        "schema_version": 1,
        "raw_run": resolved.run_dir.name,
        **normalized,
        "validation_passed": validation["validation_passed"],
        "integrity_passed": integrity_passed,
        "expected_tls_record_count": manifest.get("expected_tls_record_count"),
        "expected_mldsa_record_count": manifest.get("expected_mldsa_record_count"),
        "raw_file_count": len(raw_file_inventory) if isinstance(raw_file_inventory, list) else None,
        "errors": validation["errors"],
        "not_evaluated_reasons": normalized_reasons,
        "raw_run_checksum": validation["raw_run_checksum"],
        "exact_configuration_hash": resolved.exact_configuration_hash,
        "scientific_design_hash": resolved.scientific_design_hash,
        "validation_source": validation_source,
    }


def _quality_gate(
    integrity: dict[str, Any],
    stability: dict[str, Any],
    drift: dict[str, Any],
    bootstrap: dict[str, Any],
) -> dict[str, Any]:
    integrity_passed = all(
        integrity[key] is True
        for key in (
            "raw_checksums_valid",
            "record_counts_exact",
            "every_cryptographic_operation_successful",
            "block_balance_valid",
            "no_missing_replicates",
            "configuration_snapshot_matches_manifest",
        )
    )
    stability_passed = not any_warning(stability) and not any_warning(drift)
    bootstrap_width_reported = all(
        "relative_interval_width" in metric
        for family_name, family in bootstrap.items()
        if family_name != "schema_version"
        for case in family.values()
        for metric in case.values()
    )
    exploratory = integrity_passed and bootstrap_width_reported
    return {
        "schema_version": 1,
        "integrity_passed": integrity_passed,
        "timing_stability_passed": stability_passed,
        "calibration_usable_for_exploratory_analysis": exploratory,
        "calibration_usable_as_final_selector_cost": integrity_passed and stability_passed,
        "requirements": {
            "timing_stability_threshold": TIMING_STABILITY_THRESHOLD,
            "bootstrap_relative_width_reported": bootstrap_width_reported,
        },
        "interpretation": (
            "Integrity and exploratory usability are distinct from timing stability; "
            "failed timing stability does not invalidate retained raw evidence."
        ),
    }


def _load_or_recompute_validation(
    summary_root: Path,
    run_id: str,
    run_dir: Path,
    resolved: ResolvedCalibrationConfig,
) -> tuple[dict[str, Any], str]:
    expected_checksum = raw_run_checksum(run_dir)
    report_path = summary_root / run_id / "validation_report.json"
    if report_path.is_file():
        candidate = load_json(report_path)
        if (
            candidate.get("schema_version") == 1
            and candidate.get("raw_run") == run_id
            and candidate.get("raw_run_checksum") == expected_checksum
            and candidate.get("exact_configuration_hash") == resolved.exact_configuration_hash
        ):
            return candidate, "reused"
    return validate_raw_run(run_dir, resolved.config), "recomputed"


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    config_path = (
        None
        if args.config is None
        else args.config
        if args.config.is_absolute()
        else repo_root / args.config
    )
    raw_root = args.raw_root if args.raw_root.is_absolute() else repo_root / args.raw_root
    summary_root = (
        args.summary_root if args.summary_root.is_absolute() else repo_root / args.summary_root
    )
    artifact_root = (
        args.artifact_root if args.artifact_root.is_absolute() else repo_root / args.artifact_root
    )
    run_dir = raw_root / args.run_id
    output_dir = artifact_root / args.run_id

    resolved = resolve_raw_run_config_with_optional_external(run_dir, config_path)
    validation, validation_source = _load_or_recompute_validation(
        summary_root, args.run_id, run_dir, resolved
    )
    tls_grouped = group_tls_records(run_dir)
    mldsa_grouped = group_mldsa_records(run_dir)

    integrity = _integrity_summary(validation, resolved, validation_source)
    stability = {
        "schema_version": 1,
        "threshold": TIMING_STABILITY_THRESHOLD,
        "tls": replicate_stability(tls_grouped, TLS_METRICS),
        "mldsa": replicate_stability(mldsa_grouped, MLDSA_METRICS),
        "outlier_diagnostics": {
            "note": "Outlier diagnostics are descriptive and never remove observations.",
            "tls": outlier_diagnostics(tls_grouped, TLS_METRICS),
            "mldsa": outlier_diagnostics(mldsa_grouped, MLDSA_METRICS),
        },
    }
    drift = {
        "schema_version": 1,
        "window_size_blocks": WINDOW_SIZE_BLOCKS,
        "warning_threshold": TIMING_STABILITY_THRESHOLD,
        "tls": windowed_drift(tls_grouped, TLS_METRICS),
        "mldsa": windowed_drift(mldsa_grouped, MLDSA_METRICS),
    }
    trend = {
        "schema_version": 1,
        "note": "Theil-Sen trend is diagnostic only; raw observations are not detrended.",
        "tls": robust_trend(tls_grouped, TLS_TIMING_METRICS),
        "mldsa": robust_trend(mldsa_grouped, MLDSA_TIMING_METRICS),
    }
    bootstrap = {
        "schema_version": 1,
        "tls": bootstrap_quality(
            _load_summary(summary_root, args.run_id, "tls_campaign_summary.json")
        ),
        "mldsa": bootstrap_quality(
            _load_summary(summary_root, args.run_id, "mldsa_campaign_summary.json")
        ),
    }
    machine = machine_state_audit(run_dir)
    quality_gate = _quality_gate(integrity, stability, drift, bootstrap)
    outputs = {
        "integrity_summary.json": integrity,
        "replicate_stability.json": stability,
        "windowed_drift.json": drift,
        "robust_trend.json": trend,
        "bootstrap_quality.json": bootstrap,
        "machine_state_audit.json": machine,
        "quality_gate.json": quality_gate,
    }
    with staged_report_dir(output_dir, replace_existing=bool(args.replace_existing)) as staging:
        written: list[Path] = []
        for name, payload in outputs.items():
            path = staging / name
            atomic_write_json(path, payload)
            written.append(path)

        manifest = {
            "schema_version": 1,
            "run_id": args.run_id,
            "raw_run_checksum": raw_run_checksum(run_dir),
            "analysis_git_commit": git_commit(repo_root),
            "git_dirty": git_dirty(repo_root),
            "implementation_version": IMPLEMENTATION_VERSION,
            "exact_configuration_hash": resolved.exact_configuration_hash,
            "scientific_design_hash": resolved.scientific_design_hash,
            "validation_source": validation_source,
            "diagnostic_thresholds": {
                "timing_stability_relative_range": TIMING_STABILITY_THRESHOLD,
                "windowed_drift_relative_change": TIMING_STABILITY_THRESHOLD,
            },
            "window_size_blocks": WINDOW_SIZE_BLOCKS,
            "generated_at_utc": utc_now(),
            "generated_files": sorted(
                [path.name for path in written] + ["checksums.sha256", "quality_manifest.json"]
            ),
        }
        manifest_path = staging / "quality_manifest.json"
        atomic_write_json(manifest_path, manifest)
        written.append(manifest_path)
        write_checksums(staging, written)
    return 0 if validation["validation_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
