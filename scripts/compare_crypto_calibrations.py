#!/usr/bin/env python3
"""Compare two independent crypto calibration campaigns without automatic pooling."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.smoke_validation import atomic_write_json, write_checksums
from pqtrust_agent.metrics.artifact_io import staged_report_dir
from pqtrust_agent.metrics.bootstrap import hierarchical_bootstrap_median_ci
from pqtrust_agent.metrics.calibration_config_resolver import (
    ResolvedCalibrationConfig,
    resolve_raw_run_config,
)
from pqtrust_agent.metrics.calibration_quality import (
    MLDSA_METRICS,
    TLS_METRICS,
    group_mldsa_records,
    group_tls_records,
    replicate_relative_range,
)
from pqtrust_agent.metrics.descriptive import median
from pqtrust_agent.metrics.validation import load_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run-id", required=True)
    parser.add_argument("--confirmatory-run-id", required=True)
    parser.add_argument("--raw-root", type=Path, default=Path("runs/raw/crypto_calibration"))
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--create-combined-summary", action="store_true")
    parser.add_argument("--replace-existing", action="store_true")
    return parser.parse_args()


def _summary_root(artifact_root: Path) -> Path:
    return artifact_root / "calibration"


def _quality_root(artifact_root: Path) -> Path:
    return artifact_root / "calibration-quality"


def _native_hashes(run_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for replicate in sorted((run_dir / "replicates").iterdir()):
        state = load_json(replicate / "pre_state.json")
        observed = state.get("native_executable_hashes", {})
        if isinstance(observed, dict):
            hashes.update({str(key): str(value) for key, value in observed.items()})
    return hashes


def _case_definitions(config: Any) -> dict[str, Any]:
    return {
        "tls_groups": list(config.tls_groups),
        "mldsa_algorithms": list(config.mldsa_algorithms),
        "mldsa_message_sizes_bytes": list(config.mldsa_message_sizes_bytes),
    }


def _record_design(config: Any) -> dict[str, Any]:
    return {
        "expected_tls_records_per_replicate": config.expected_tls_records_per_replicate(),
        "expected_mldsa_records_per_replicate": config.expected_mldsa_records_per_replicate(),
        "expected_tls_records_total": config.expected_tls_records_total(),
        "expected_mldsa_records_total": config.expected_mldsa_records_total(),
        "replicate_count": len(config.replicates),
        "measured_blocks": config.measured_blocks,
        "warmups_per_case": config.warmups_per_case,
    }


def _quality_integrity(artifact_root: Path, run_id: str) -> dict[str, Any]:
    gate_path = _quality_root(artifact_root) / run_id / "quality_gate.json"
    integrity_path = _quality_root(artifact_root) / run_id / "integrity_summary.json"
    if not gate_path.is_file() or not integrity_path.is_file():
        return {
            "run_id": run_id,
            "integrity_passed": False,
            "error": "missing quality audit integrity report",
        }
    gate = load_json(gate_path)
    integrity = load_json(integrity_path)
    return {
        "run_id": run_id,
        "integrity_passed": gate.get("integrity_passed") is True,
        "raw_checksums_valid": integrity.get("raw_checksums_valid"),
        "record_counts_exact": integrity.get("record_counts_exact"),
        "block_balance_valid": integrity.get("block_balance_valid"),
        "every_cryptographic_operation_successful": integrity.get(
            "every_cryptographic_operation_successful"
        ),
        "no_missing_replicates": integrity.get("no_missing_replicates"),
        "configuration_snapshot_matches_manifest": integrity.get(
            "configuration_snapshot_matches_manifest"
        ),
    }


def compatibility_report(baseline_dir: Path, confirmatory_dir: Path) -> dict[str, Any]:
    baseline = resolve_raw_run_config(baseline_dir)
    confirmatory = resolve_raw_run_config(confirmatory_dir)
    return compatibility_report_for_resolved(baseline, confirmatory, None)


def compatibility_report_for_resolved(
    baseline: ResolvedCalibrationConfig,
    confirmatory: ResolvedCalibrationConfig,
    integrity: dict[str, Any] | None,
) -> dict[str, Any]:
    baseline_manifest = baseline.manifest
    confirmatory_manifest = confirmatory.manifest
    baseline_config = baseline.config
    confirmatory_config = confirmatory.config
    catalog_hashes_match = (
        baseline_manifest.get("catalog_hash") == confirmatory_manifest.get("catalog_hash")
    )
    openssl_versions_match = (
        baseline_manifest.get("openssl_version") == confirmatory_manifest.get("openssl_version")
    )
    native_executable_hashes_match = _native_hashes(baseline.run_dir) == _native_hashes(
        confirmatory.run_dir
    )
    case_definitions_match = _case_definitions(baseline_config) == _case_definitions(
        confirmatory_config
    )
    record_designs_match = _record_design(baseline_config) == _record_design(confirmatory_config)
    scientific_design_hashes_match = (
        baseline.scientific_design_hash == confirmatory.scientific_design_hash
    )
    exact_configuration_hashes_match = (
        baseline.exact_configuration_hash == confirmatory.exact_configuration_hash
    )
    both_integrity_passed = (
        integrity is None
        or (
            integrity.get("baseline", {}).get("integrity_passed") is True
            and integrity.get("confirmatory", {}).get("integrity_passed") is True
        )
    )
    compatible = (
        scientific_design_hashes_match
        and catalog_hashes_match
        and openssl_versions_match
        and native_executable_hashes_match
        and case_definitions_match
        and record_designs_match
        and both_integrity_passed
    )
    permitted_exact_difference = (
        not exact_configuration_hashes_match
        and scientific_design_hashes_match
        and case_definitions_match
        and record_designs_match
    )
    interpretation = (
        "Exact execution configurations differ because permitted non-design fields differ, "
        "while scientific case design is identical."
        if permitted_exact_difference
        else "Exact execution configurations and scientific case design match."
        if exact_configuration_hashes_match and scientific_design_hashes_match
        else "Scientific design differs; cross-run comparison is not compatible."
    )
    return {
        "baseline_exact_configuration_hash": baseline.exact_configuration_hash,
        "confirmatory_exact_configuration_hash": confirmatory.exact_configuration_hash,
        "exact_configuration_hashes_match": exact_configuration_hashes_match,
        "baseline_scientific_design_hash": baseline.scientific_design_hash,
        "confirmatory_scientific_design_hash": confirmatory.scientific_design_hash,
        "scientific_design_hashes_match": scientific_design_hashes_match,
        "catalog_hashes_match": catalog_hashes_match,
        "OpenSSL_versions_match": openssl_versions_match,
        "native_executable_hashes_match": native_executable_hashes_match,
        "case_definitions_match": case_definitions_match,
        "record_designs_match": record_designs_match,
        "comparison_compatible": compatible,
        "compatibility_interpretation": interpretation,
        "details": {
            "catalog_hash": {
                "baseline": baseline_manifest.get("catalog_hash"),
                "confirmatory": confirmatory_manifest.get("catalog_hash"),
            },
            "openssl_version": {
                "baseline": baseline_manifest.get("openssl_version"),
                "confirmatory": confirmatory_manifest.get("openssl_version"),
            },
            "benchmark_executable_hashes": {
                "baseline": _native_hashes(baseline.run_dir),
                "confirmatory": _native_hashes(confirmatory.run_dir),
            },
            "case_definitions": {
                "baseline": _case_definitions(baseline_config),
                "confirmatory": _case_definitions(confirmatory_config),
            },
            "record_designs": {
                "baseline": _record_design(baseline_config),
                "confirmatory": _record_design(confirmatory_config),
            },
        },
    }


def _load_campaign(summary_root: Path, run_id: str, name: str) -> dict[str, Any]:
    return load_json(summary_root / run_id / name)


def _stability_for(summary: dict[str, Any], case: str, metric: str) -> bool:
    medians = [float(value) for value in summary[case][metric]["replicate_medians"]]
    return bool(replicate_relative_range(medians)["relative_replicate_range"] <= 0.10)


def compare_summaries(
    baseline_summary: dict[str, Any],
    confirmatory_summary: dict[str, Any],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case in sorted(baseline_summary):
        output[case] = {}
        for metric in sorted(baseline_summary[case]):
            base = baseline_summary[case][metric]
            conf = confirmatory_summary[case][metric]
            base_median = float(base["campaign_median_of_replicate_medians"])
            conf_median = float(conf["campaign_median_of_replicate_medians"])
            base_ci = base["hierarchical_bootstrap_95ci"]
            conf_ci = conf["hierarchical_bootstrap_95ci"]
            base_lower = float(base_ci["lower"])
            base_upper = float(base_ci["upper"])
            conf_lower = float(conf_ci["lower"])
            conf_upper = float(conf_ci["upper"])
            output[case][metric] = {
                "baseline_campaign_median": base_median,
                "confirmatory_campaign_median": conf_median,
                "absolute_difference": conf_median - base_median,
                "relative_difference": 0.0
                if base_median == 0
                else (conf_median - base_median) / base_median,
                "baseline_confidence_interval": base_ci,
                "confirmatory_confidence_interval": conf_ci,
                "interval_overlap": max(base_lower, conf_lower) <= min(base_upper, conf_upper),
                "baseline_stability_within_10_percent": _stability_for(
                    baseline_summary, case, metric
                ),
                "confirmatory_stability_within_10_percent": _stability_for(
                    confirmatory_summary, case, metric
                ),
            }
    return output


def _timing_stability(tls: dict[str, Any], mldsa: dict[str, Any]) -> dict[str, Any]:
    baseline_values = [
        metric["baseline_stability_within_10_percent"]
        for family in (tls, mldsa)
        for case in family.values()
        for metric in case.values()
    ]
    confirmatory_values = [
        metric["confirmatory_stability_within_10_percent"]
        for family in (tls, mldsa)
        for case in family.values()
        for metric in case.values()
    ]
    return {
        "threshold": 0.10,
        "baseline_stability_within_10_percent": all(baseline_values),
        "confirmatory_stability_within_10_percent": all(confirmatory_values),
        "measured_timing_stability_passed": all(baseline_values) and all(confirmatory_values),
        "interpretation": (
            "Timing instability is reported as measured and does not alter raw integrity."
        ),
    }


def _replicate_values(
    grouped: dict[str, dict[str, list[dict[str, Any]]]], metrics: tuple[str, ...]
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for metric in metrics:
            values = [
                [float(record[metric]) for record in records]
                for _replicate, records in sorted(replicates.items())
            ]
            replicate_medians = [median(rep) for rep in values]
            output[case][metric] = {
                "replicate_medians": replicate_medians,
                "campaign_median_of_replicate_medians": median(replicate_medians),
                "hierarchical_bootstrap_95ci": hierarchical_bootstrap_median_ci(values),
                "replicate_identity_preserved": [
                    replicate for replicate, _records in sorted(replicates.items())
                ],
            }
    return output


def _prefix_baseline_replicates(
    grouped: dict[str, dict[str, list[dict[str, Any]]]],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    return {
        case: {
            **{
                f"baseline-{rep}": records
                for rep, records in replicates.items()
                if not rep.startswith("confirmatory-")
            },
            **{
                rep: records
                for rep, records in replicates.items()
                if rep.startswith("confirmatory-")
            },
        }
        for case, replicates in grouped.items()
    }


def combined_summary(baseline_dir: Path, confirmatory_dir: Path) -> dict[str, Any]:
    tls_grouped = group_tls_records(baseline_dir)
    mldsa_grouped = group_mldsa_records(baseline_dir)
    for case, replicates in group_tls_records(confirmatory_dir).items():
        tls_grouped.setdefault(case, {}).update(
            {f"confirmatory-{rep}": records for rep, records in replicates.items()}
        )
    for case, replicates in group_mldsa_records(confirmatory_dir).items():
        mldsa_grouped.setdefault(case, {}).update(
            {f"confirmatory-{rep}": records for rep, records in replicates.items()}
        )
    tls_grouped = _prefix_baseline_replicates(tls_grouped)
    mldsa_grouped = _prefix_baseline_replicates(mldsa_grouped)
    return {
        "schema_version": 1,
        "pooling_note": "Explicit six-replicate summary; campaign identity is preserved.",
        "tls": _replicate_values(tls_grouped, TLS_METRICS),
        "mldsa": _replicate_values(mldsa_grouped, MLDSA_METRICS),
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    raw_root = args.raw_root if args.raw_root.is_absolute() else repo_root / args.raw_root
    artifact_root = (
        args.artifact_root if args.artifact_root.is_absolute() else repo_root / args.artifact_root
    )
    output_dir = args.output_dir if args.output_dir.is_absolute() else repo_root / args.output_dir

    baseline_dir = raw_root / args.baseline_run_id
    confirmatory_dir = raw_root / args.confirmatory_run_id
    baseline_resolved = resolve_raw_run_config(baseline_dir)
    confirmatory_resolved = resolve_raw_run_config(confirmatory_dir)
    integrity = {
        "baseline": _quality_integrity(artifact_root, args.baseline_run_id),
        "confirmatory": _quality_integrity(artifact_root, args.confirmatory_run_id),
    }
    compatibility = compatibility_report_for_resolved(
        baseline_resolved, confirmatory_resolved, integrity
    )

    summary_root = _summary_root(artifact_root)
    tls = compare_summaries(
        _load_campaign(summary_root, args.baseline_run_id, "tls_campaign_summary.json"),
        _load_campaign(summary_root, args.confirmatory_run_id, "tls_campaign_summary.json"),
    )
    mldsa = compare_summaries(
        _load_campaign(summary_root, args.baseline_run_id, "mldsa_campaign_summary.json"),
        _load_campaign(summary_root, args.confirmatory_run_id, "mldsa_campaign_summary.json"),
    )
    timing = _timing_stability(tls, mldsa)
    report: dict[str, Any] = {
        "schema_version": 1,
        "baseline": {
            "run_id": args.baseline_run_id,
            "exact_configuration_hash": baseline_resolved.exact_configuration_hash,
            "scientific_design_hash": baseline_resolved.scientific_design_hash,
        },
        "confirmatory": {
            "run_id": args.confirmatory_run_id,
            "exact_configuration_hash": confirmatory_resolved.exact_configuration_hash,
            "scientific_design_hash": confirmatory_resolved.scientific_design_hash,
        },
        "compatibility": compatibility,
        "integrity": integrity,
        "tls": tls,
        "mldsa": mldsa,
        "timing_stability": timing,
        "combined_summary": {
            "created": False,
            "automatic": False,
            "explicit_option_required": True,
        },
        "warnings": [],
        "errors": [],
    }
    if args.create_combined_summary:
        if not compatibility["comparison_compatible"]:
            report["errors"].append("combined summary requires scientific-design compatibility")
        else:
            report["combined_summary"] = {
                "created": True,
                "automatic": False,
                "explicit_option_required": True,
                "timing_stability": timing,
            }

    with staged_report_dir(output_dir, replace_existing=bool(args.replace_existing)) as staging:
        written: list[Path] = []
        comparison_path = staging / "cross_run_comparison.json"
        atomic_write_json(comparison_path, report)
        written.append(comparison_path)
        if args.create_combined_summary and compatibility["comparison_compatible"]:
            combined_path = staging / "combined_six_replicate_summary.json"
            atomic_write_json(combined_path, combined_summary(baseline_dir, confirmatory_dir))
            written.append(combined_path)
        write_checksums(staging, written)
    return 0 if compatibility["comparison_compatible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
