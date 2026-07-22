#!/usr/bin/env python3
"""Analyze validated Stage 3B calibration evidence with standard-library statistics."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.smoke_validation import atomic_write_json, write_checksums
from pqtrust_agent.metrics.bootstrap import (
    BOOTSTRAP_ITERATIONS,
    BOOTSTRAP_SEED,
    hierarchical_bootstrap_median_ci,
)
from pqtrust_agent.metrics.calibration_config_resolver import (
    resolve_raw_run_config_with_optional_external,
)
from pqtrust_agent.metrics.descriptive import (
    QUANTILE_DEFINITION,
    describe,
    drift_report,
    identical_value_report,
    outlier_count_3mad,
    replicate_median_summary,
)
from pqtrust_agent.metrics.run_manifest import git_commit, git_dirty, utc_now
from pqtrust_agent.metrics.validation import load_jsonl, raw_run_checksum, validate_raw_run
from pqtrust_agent.models.catalog import load_profile_catalog

TLS_METRICS = (
    "wall_time_ns",
    "process_cpu_time_ns",
    "client_to_server_bytes",
    "server_to_client_bytes",
    "total_handshake_bytes",
)
MLDSA_METRICS = ("sign_time_ns", "verify_time_ns", "signature_size_bytes")


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
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts/calibration"))
    return parser.parse_args()


def _group_tls(run_dir: Path) -> dict[str, dict[int, list[dict[str, Any]]]]:
    grouped: dict[str, dict[int, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for index, replicate_dir in enumerate(sorted((run_dir / "replicates").iterdir()), start=1):
        for record in load_jsonl(replicate_dir / "tls_handshakes.jsonl"):
            grouped[str(record["requested_group"])][index].append(record)
    return grouped


def _group_mldsa(run_dir: Path) -> dict[str, dict[int, list[dict[str, Any]]]]:
    grouped: dict[str, dict[int, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for index, replicate_dir in enumerate(sorted((run_dir / "replicates").iterdir()), start=1):
        for record in load_jsonl(replicate_dir / "mldsa.jsonl"):
            case = f"{record['algorithm']}:{record['message_size_bytes']}"
            grouped[case][index].append(record)
    return grouped


def _by_replicate(
    grouped: dict[str, dict[int, list[dict[str, Any]]]],
    metrics: tuple[str, ...],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for replicate, records in replicates.items():
            output[case][f"replicate-{replicate:02d}"] = {}
            for metric in metrics:
                output[case][f"replicate-{replicate:02d}"][metric] = describe(
                    [float(record[metric]) for record in records]
                )
    return output


def _campaign(
    grouped: dict[str, dict[int, list[dict[str, Any]]]],
    metrics: tuple[str, ...],
    constant_metrics: set[str],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case, replicates in grouped.items():
        output[case] = {}
        for metric in metrics:
            replicate_values = [
                [float(record[metric]) for record in replicates[index]]
                for index in sorted(replicates)
            ]
            all_values = [value for values in replicate_values for value in values]
            summary = replicate_median_summary(replicate_values)
            summary["hierarchical_bootstrap_95ci"] = hierarchical_bootstrap_median_ci(
                replicate_values
            )
            if metric in constant_metrics:
                summary["constant_distribution"] = identical_value_report(all_values)
            output[case][metric] = summary
    return output


def _diagnostics(
    grouped: dict[str, dict[int, list[dict[str, Any]]]],
    metrics: tuple[str, ...],
) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {}
    for case, replicates in grouped.items():
        diagnostics[case] = {}
        for metric in metrics:
            replicate_medians = [
                describe([float(record[metric]) for record in records])["median"]
                for _index, records in sorted(replicates.items())
            ]
            all_records = [
                record
                for _index, records in sorted(replicates.items())
                for record in records
            ]
            values = [float(record[metric]) for record in all_records]
            diagnostics[case][metric] = {
                "outliers_3mad": outlier_count_3mad(values),
                **drift_report(all_records, metric, [float(value) for value in replicate_medians]),
            }
    return diagnostics


def _profile_artifact(
    repo_root: Path,
    tls_summary: dict[str, Any],
    raw_checksum: str,
    run_id: str,
) -> dict[str, Any]:
    catalog = load_profile_catalog(repo_root / "configs/profiles/trust_profiles.yaml")
    records: list[dict[str, Any]] = []
    for profile in catalog.profiles:
        group = profile.tls_group
        summary = tls_summary[group]
        records.append(
            {
                "profile_id": profile.profile_id,
                "tls_group": group,
                "tls_wall_time_campaign_median": summary["wall_time_ns"][
                    "campaign_median_of_replicate_medians"
                ],
                "tls_wall_time_95ci": summary["wall_time_ns"]["hierarchical_bootstrap_95ci"],
                "process_cpu_time_campaign_median": summary["process_cpu_time_ns"][
                    "campaign_median_of_replicate_medians"
                ],
                "process_cpu_time_95ci": summary["process_cpu_time_ns"][
                    "hierarchical_bootstrap_95ci"
                ],
                "total_handshake_bytes": summary["total_handshake_bytes"].get(
                    "constant_distribution"
                ),
                "source_raw_run_id": run_id,
                "raw_run_checksum": raw_checksum,
                "catalog_hash": catalog.catalog_hash(),
                "contract_evidence": {
                    "mldsa_summary_files": [
                        "mldsa_by_replicate.json",
                        "mldsa_campaign_summary.json",
                    ],
                    "note": "No ML-DSA message size is selected as contract cost in Stage 3B.",
                },
            }
        )
    return {"schema_version": 1, "profiles": records}


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
    artifact_root = (
        args.artifact_root if args.artifact_root.is_absolute() else repo_root / args.artifact_root
    )
    run_dir = raw_root / args.run_id
    output_dir = artifact_root / args.run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = resolve_raw_run_config_with_optional_external(run_dir, config_path)
    config = resolved.config
    validation_report = validate_raw_run(run_dir, config)
    atomic_write_json(output_dir / "validation_report.json", validation_report)
    if validation_report["validation_passed"] is not True:
        return 1

    tls_grouped = _group_tls(run_dir)
    mldsa_grouped = _group_mldsa(run_dir)
    tls_by_replicate = _by_replicate(tls_grouped, TLS_METRICS)
    tls_campaign = _campaign(tls_grouped, TLS_METRICS, {"total_handshake_bytes"})
    mldsa_by_replicate = _by_replicate(mldsa_grouped, MLDSA_METRICS)
    mldsa_campaign = _campaign(mldsa_grouped, MLDSA_METRICS, {"signature_size_bytes"})
    drift = {
        "tls": _diagnostics(tls_grouped, TLS_METRICS),
        "mldsa": _diagnostics(mldsa_grouped, MLDSA_METRICS),
    }
    raw_checksum = raw_run_checksum(run_dir)
    outputs = {
        "tls_by_replicate.json": tls_by_replicate,
        "tls_campaign_summary.json": tls_campaign,
        "mldsa_by_replicate.json": mldsa_by_replicate,
        "mldsa_campaign_summary.json": mldsa_campaign,
        "drift_diagnostics.json": drift,
        "profile_crypto_calibration.json": _profile_artifact(
            repo_root, tls_campaign, raw_checksum, args.run_id
        ),
    }
    written: list[Path] = [output_dir / "validation_report.json"]
    for name, payload in outputs.items():
        path = output_dir / name
        atomic_write_json(path, payload)
        written.append(path)
    manifest = {
        "schema_version": 1,
        "raw_run_checksum": raw_checksum,
        "analysis_implementation_version": 1,
        "git_commit": git_commit(repo_root),
        "git_dirty": git_dirty(repo_root),
        "analysis_configuration": {
            "exact_configuration_hash": config.exact_configuration_hash(),
            "legacy_configuration_hash": config.config_hash(),
            "scientific_design_hash": config.scientific_design_hash(),
        },
        "bootstrap_seed": BOOTSTRAP_SEED,
        "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
        "quantile_definition": QUANTILE_DEFINITION,
        "generated_at_utc": utc_now(),
        "generated_files": sorted(path.name for path in written),
        "validation_status": validation_report["validation_passed"],
    }
    atomic_write_json(output_dir / "analysis_manifest.json", manifest)
    written.append(output_dir / "analysis_manifest.json")
    write_checksums(output_dir, written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
