"""Validation for immutable Stage 3B raw calibration evidence."""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, cast

from pqtrust_agent.crypto.smoke_validation import sha256_file, verify_checksums
from pqtrust_agent.metrics.calibration_models import CryptoCalibrationConfig


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line:
            continue
        loaded = json.loads(line)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}:{line_number}: JSONL record must be an object")
        records.append(loaded)
    return records


def load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


def checksum_inventory(checksum_path: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, rel = line.split(maxsplit=1)
        inventory[rel.strip()] = digest
    return inventory


def raw_run_checksum(run_dir: Path) -> str:
    checksum_path = run_dir / "checksums.sha256"
    return sha256_file(checksum_path)


def _finite_positive(record: dict[str, Any], field: str, errors: list[str]) -> None:
    value = record.get(field)
    if not isinstance(value, int | float) or isinstance(value, bool):
        errors.append(f"sequence {record.get('sequence')}: {field} must be numeric")
        return
    if not math.isfinite(float(value)) or value <= 0:
        errors.append(f"sequence {record.get('sequence')}: {field} must be finite and positive")


def _validate_sequences(records: list[dict[str, Any]], errors: list[str], label: str) -> None:
    sequences = [record.get("sequence") for record in records]
    if not all(
        isinstance(sequence, int) and not isinstance(sequence, bool) for sequence in sequences
    ):
        errors.append(f"{label}: sequence numbers must be integers")
        return
    integer_sequences = [cast(int, sequence) for sequence in sequences]
    if len(integer_sequences) != len(set(integer_sequences)):
        errors.append(f"{label}: duplicate sequence numbers")
    if sorted(integer_sequences) != list(range(len(integer_sequences))):
        errors.append(f"{label}: sequence numbers must be contiguous from zero")


def _validate_tls_records(
    records: list[dict[str, Any]],
    config: CryptoCalibrationConfig,
    errors: list[str],
    replicate: int,
) -> None:
    if len(records) != config.expected_tls_records_per_replicate():
        errors.append(f"replicate {replicate}: expected 1000 TLS records, observed {len(records)}")
    _validate_sequences(records, errors, f"replicate {replicate} TLS")
    expected_groups = set(config.tls_groups)
    observed_cases = {record.get("requested_group") for record in records}
    if observed_cases != expected_groups:
        errors.append(f"replicate {replicate}: missing or additional TLS cases")
    for block in range(config.measured_blocks):
        block_records = [record for record in records if record.get("block") == block]
        if Counter(record.get("requested_group") for record in block_records) != Counter(
            expected_groups
        ):
            errors.append(f"replicate {replicate}: TLS block {block} is not balanced")
    for record in records:
        requested = str(record.get("requested_group", ""))
        negotiated = str(record.get("negotiated_group", ""))
        server = str(record.get("server_negotiated_group", ""))
        if requested.casefold() != negotiated.casefold():
            errors.append(f"sequence {record.get('sequence')}: requested/negotiated group mismatch")
        if negotiated.casefold() != server.casefold():
            errors.append(f"sequence {record.get('sequence')}: client/server group mismatch")
        if record.get("tls_version") != config.expected_tls_version:
            errors.append(f"sequence {record.get('sequence')}: unexpected TLS version")
        if record.get("cipher_suite") != config.tls_cipher_suite:
            errors.append(f"sequence {record.get('sequence')}: unexpected TLS cipher suite")
        if record.get("certificate_verify_result") != 0:
            errors.append(f"sequence {record.get('sequence')}: certificate result is not zero")
        if record.get("session_reused") is not False:
            errors.append(f"sequence {record.get('sequence')}: session reuse is not false")
        if record.get("success") is not True:
            errors.append(f"sequence {record.get('sequence')}: TLS success is not true")
        for field in (
            "wall_time_ns",
            "process_cpu_time_ns",
            "client_to_server_bytes",
            "server_to_client_bytes",
            "total_handshake_bytes",
        ):
            _finite_positive(record, field, errors)


def _validate_mldsa_records(
    records: list[dict[str, Any]],
    config: CryptoCalibrationConfig,
    errors: list[str],
    replicate: int,
) -> None:
    if len(records) != config.expected_mldsa_records_per_replicate():
        errors.append(
            f"replicate {replicate}: expected 1200 ML-DSA records, observed {len(records)}"
        )
    _validate_sequences(records, errors, f"replicate {replicate} ML-DSA")
    expected_cases = {
        (algorithm, size)
        for algorithm in config.mldsa_algorithms
        for size in config.mldsa_message_sizes_bytes
    }
    observed_cases = {
        (record.get("algorithm"), record.get("message_size_bytes")) for record in records
    }
    if observed_cases != expected_cases:
        errors.append(f"replicate {replicate}: missing or additional ML-DSA cases")
    for block in range(config.measured_blocks):
        block_records = [record for record in records if record.get("block") == block]
        observed = Counter(
            (record.get("algorithm"), record.get("message_size_bytes"))
            for record in block_records
        )
        if observed != Counter(expected_cases):
            errors.append(f"replicate {replicate}: ML-DSA block {block} is not balanced")
    for record in records:
        for field in ("sign_time_ns", "verify_time_ns", "signature_size_bytes"):
            _finite_positive(record, field, errors)
        if record.get("verification_success") is not True:
            errors.append(f"sequence {record.get('sequence')}: ML-DSA verification failed")
        if record.get("negative_self_test_passed") is not True:
            errors.append(f"sequence {record.get('sequence')}: negative self-test failed")
        if record.get("success") is not True:
            errors.append(f"sequence {record.get('sequence')}: ML-DSA success is not true")


def _validate_checksums(run_dir: Path, errors: list[str]) -> None:
    checksum_path = run_dir / "checksums.sha256"
    try:
        verify_checksums(checksum_path)
    except Exception as exc:
        errors.append(f"checksum validation failed: {exc}")
        return
    recorded = set(checksum_inventory(checksum_path))
    actual = {
        path.relative_to(run_dir).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if recorded != actual:
        errors.append("checksum inventory does not match raw-run file inventory")


def _check_value(errors: list[str]) -> bool:
    return not errors


def validate_raw_run(run_dir: Path, config: CryptoCalibrationConfig) -> dict[str, Any]:
    errors: list[str] = []
    check_errors: dict[str, list[str]] = {
        "raw_checksums_valid": [],
        "record_counts_exact": [],
        "block_balance_valid": [],
        "every_cryptographic_operation_successful": [],
        "no_missing_replicates": [],
        "configuration_snapshot_matches_manifest": [],
    }
    not_evaluated_reasons: dict[str, str] = {}
    if not run_dir.is_dir():
        raise FileNotFoundError(run_dir)
    _validate_checksums(run_dir, check_errors["raw_checksums_valid"])
    manifest = load_json(run_dir / "run_manifest.json")
    manifest_hashes = {
        value
        for value in (
            manifest.get("exact_configuration_hash"),
            manifest.get("calibration_configuration_hash"),
        )
        if isinstance(value, str)
    }
    if not manifest_hashes.intersection(
        {config.exact_configuration_hash(), config.config_hash()}
    ):
        check_errors["configuration_snapshot_matches_manifest"].append(
            "run manifest configuration hash mismatch"
        )
    if manifest.get("replicate_count") != 3:
        check_errors["no_missing_replicates"].append("run manifest replicate count is not three")
    replicates_dir = run_dir / "replicates"
    if not replicates_dir.is_dir():
        check_errors["no_missing_replicates"].append("raw run is missing replicates directory")
        errors = [error for values in check_errors.values() for error in values]
        return {
            "schema_version": 1,
            "raw_run": run_dir.name,
            "validation_passed": False,
            "errors": errors,
            "checks": {
                key: (
                    _check_value(value)
                    if key != "configuration_snapshot_matches_manifest"
                    else False
                )
                for key, value in check_errors.items()
            },
            "not_evaluated_reasons": not_evaluated_reasons,
            "expected_replicates": 3,
            "expected_tls_records_per_replicate": config.expected_tls_records_per_replicate(),
            "expected_mldsa_records_per_replicate": (
                config.expected_mldsa_records_per_replicate()
            ),
            "raw_run_checksum": (
                raw_run_checksum(run_dir) if (run_dir / "checksums.sha256").exists() else None
            ),
        }
    replicate_dirs = sorted(path for path in replicates_dir.iterdir() if path.is_dir())
    if [path.name for path in replicate_dirs] != ["replicate-01", "replicate-02", "replicate-03"]:
        check_errors["no_missing_replicates"].append(
            "raw run must contain exactly three replicate directories"
        )
    for index, replicate_dir in enumerate(replicate_dirs, start=1):
        tls_records = load_jsonl(replicate_dir / "tls_handshakes.jsonl")
        mldsa_records = load_jsonl(replicate_dir / "mldsa.jsonl")
        tls_errors: list[str] = []
        mldsa_errors: list[str] = []
        _validate_tls_records(tls_records, config, tls_errors, index)
        _validate_mldsa_records(mldsa_records, config, mldsa_errors, index)
        for error in tls_errors + mldsa_errors:
            if "expected" in error and "records" in error:
                check_errors["record_counts_exact"].append(error)
            elif "block" in error and "balanced" in error:
                check_errors["block_balance_valid"].append(error)
            elif (
                "success" in error
                or "verification failed" in error
                or "negative self-test failed" in error
                or "certificate result" in error
                or "requested/negotiated" in error
                or "client/server" in error
                or "unexpected TLS" in error
                or "session reuse" in error
            ):
                check_errors["every_cryptographic_operation_successful"].append(error)
            else:
                check_errors["every_cryptographic_operation_successful"].append(error)
        for metadata_name in ("tls_batch_metadata.json", "mldsa_batch_metadata.json"):
            metadata = load_json(replicate_dir / metadata_name)
            command = " ".join(str(item) for item in metadata.get("argv", []))
            if (
                "OpenSSL 3.5.7" not in json.dumps(metadata)
                and ".local/openssl-3.5.7" not in command
            ):
                check_errors["every_cryptographic_operation_successful"].append(
                    f"replicate {index}: {metadata_name} lacks local OpenSSL evidence"
                )
    errors = [error for values in check_errors.values() for error in values]
    checks: dict[str, bool | None] = {
        key: _check_value(value) for key, value in check_errors.items()
    }
    report = {
        "schema_version": 1,
        "raw_run": run_dir.name,
        "validation_passed": not errors,
        "errors": errors,
        "checks": checks,
        "not_evaluated_reasons": not_evaluated_reasons,
        "expected_replicates": 3,
        "expected_tls_records_per_replicate": config.expected_tls_records_per_replicate(),
        "expected_mldsa_records_per_replicate": config.expected_mldsa_records_per_replicate(),
        "exact_configuration_hash": config.exact_configuration_hash(),
        "legacy_configuration_hash": config.config_hash(),
        "scientific_design_hash": config.scientific_design_hash(),
        "raw_run_checksum": (
            raw_run_checksum(run_dir) if (run_dir / "checksums.sha256").exists() else None
        ),
    }
    return report
