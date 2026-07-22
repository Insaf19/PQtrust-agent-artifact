"""Typed wrappers around Stage 3A native benchmark binaries."""

from __future__ import annotations

import json
import math
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqtrust_agent.tls_groups import (
    canonical_tls_group,
    require_matching_tls_groups,
)


class NativeExecutionError(RuntimeError):
    """Raised when a native benchmark process fails or returns invalid output."""

    def __init__(self, message: str, *, command: Sequence[str], stderr: str) -> None:
        super().__init__(message)
        self.command = list(command)
        self.stderr = stderr


@dataclass(frozen=True)
class NativeResult:
    command: list[str]
    stdout: str
    stderr: str
    records: list[dict[str, Any]]


class NativeRunner:
    """Run native binaries without a shell and validate their JSONL output."""

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        command: Sequence[str],
        output_path: Path,
        benchmark: str,
        *,
        cwd: Path | None = None,
    ) -> NativeResult:
        try:
            completed = subprocess.run(
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            raise NativeExecutionError(
                f"native benchmark timed out after {self.timeout_seconds} seconds",
                command=command,
                stderr=stderr,
            ) from exc

        if completed.returncode != 0:
            raise NativeExecutionError(
                f"native benchmark exited with {completed.returncode}",
                command=command,
                stderr=completed.stderr,
            )

        records = load_jsonl(output_path)
        if benchmark == "tls13_handshake":
            validate_tls_records(records, expected_groups=None)
        elif benchmark == "mldsa":
            validate_mldsa_records(records, expected_cases=None)
        else:
            raise ValueError(f"unknown benchmark: {benchmark}")
        return NativeResult(
            command=list(command),
            stdout=completed.stdout,
            stderr=completed.stderr,
            records=records,
        )


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


def _require_bool(record: dict[str, Any], field: str, errors: list[str]) -> bool:
    value = record.get(field)
    if not isinstance(value, bool):
        errors.append(f"sequence {record.get('sequence')}: {field} must be a boolean")
        return False
    return value


def _require_int(record: dict[str, Any], field: str, errors: list[str]) -> int:
    value = record.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(f"sequence {record.get('sequence')}: {field} must be an integer")
        return 0
    return value


def _require_nonnegative_number(record: dict[str, Any], field: str, errors: list[str]) -> float:
    value = record.get(field)
    if not isinstance(value, int | float) or isinstance(value, bool):
        errors.append(f"sequence {record.get('sequence')}: {field} must be numeric")
        return 0.0
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        errors.append(f"sequence {record.get('sequence')}: {field} must be finite and nonnegative")
    return numeric


def _is_valid_json_string(value: str) -> bool:
    if any(ord(character) < 0x20 for character in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _require_nonempty_valid_string(
    record: dict[str, Any],
    field: str,
    errors: list[str],
) -> str | None:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        errors.append(f"sequence {record.get('sequence')}: {field} must be nonempty")
        return None
    if not _is_valid_json_string(value):
        errors.append(f"sequence {record.get('sequence')}: {field} must be valid UTF-8 JSON text")
        return None
    return value


def _validate_sequences(records: Sequence[dict[str, Any]], errors: list[str]) -> None:
    seen: set[int] = set()
    for record in records:
        sequence = _require_int(record, "sequence", errors)
        if sequence in seen:
            errors.append(f"duplicate sequence number: {sequence}")
        seen.add(sequence)


def validate_tls_records(
    records: Sequence[dict[str, Any]],
    expected_groups: Iterable[str] | None,
) -> list[str]:
    errors: list[str] = []
    expected_group_set = (
        {canonical_tls_group(group) for group in expected_groups}
        if expected_groups is not None
        else None
    )
    observed_groups: set[str] = set()
    _validate_sequences(records, errors)

    for record in records:
        if record.get("benchmark") != "tls13_handshake":
            errors.append(f"sequence {record.get('sequence')}: benchmark must be tls13_handshake")
        requested = _require_nonempty_valid_string(record, "requested_group", errors)
        negotiated = _require_nonempty_valid_string(record, "negotiated_group", errors)
        server_negotiated = record.get("server_negotiated_group")
        if server_negotiated is not None:
            server_negotiated = _require_nonempty_valid_string(
                record,
                "server_negotiated_group",
                errors,
            )
        if requested is None:
            continue
        try:
            observed_groups.add(canonical_tls_group(requested))
            if negotiated is None:
                errors.append(f"sequence {record.get('sequence')}: negotiated group mismatch")
            else:
                require_matching_tls_groups(
                    requested=requested,
                    negotiated=negotiated,
                    server_negotiated=server_negotiated
                    if isinstance(server_negotiated, str)
                    else None,
                )
        except ValueError as exc:
            errors.append(f"sequence {record.get('sequence')}: {exc}")
        if record.get("tls_version") != "TLSv1.3":
            errors.append(f"sequence {record.get('sequence')}: unexpected TLS version")
        if record.get("cipher_suite") != "TLS_AES_256_GCM_SHA384":
            errors.append(f"sequence {record.get('sequence')}: unexpected TLS cipher suite")
        if _require_bool(record, "session_reused", errors):
            errors.append(f"sequence {record.get('sequence')}: session was reused")
        if not _require_bool(record, "success", errors):
            errors.append(f"sequence {record.get('sequence')}: TLS handshake failed")
        if _require_int(record, "certificate_verify_result", errors) != 0:
            errors.append(f"sequence {record.get('sequence')}: certificate verification failed")
        total = _require_nonnegative_number(record, "total_handshake_bytes", errors)
        c2s = _require_nonnegative_number(record, "client_to_server_bytes", errors)
        s2c = _require_nonnegative_number(record, "server_to_client_bytes", errors)
        if total <= 0 or c2s <= 0 or s2c <= 0:
            errors.append(f"sequence {record.get('sequence')}: successful handshake has zero bytes")
        _require_nonnegative_number(record, "wall_time_ns", errors)
        _require_nonnegative_number(record, "process_cpu_time_ns", errors)

    if expected_group_set is not None and observed_groups != expected_group_set:
        errors.append(
            f"missing measured TLS groups: expected {sorted(expected_group_set)}, "
            f"observed {sorted(observed_groups)}"
        )
    if errors:
        raise ValueError("; ".join(errors))
    return errors


def validate_mldsa_records(
    records: Sequence[dict[str, Any]],
    expected_cases: Iterable[tuple[str, int]] | None,
) -> list[str]:
    errors: list[str] = []
    expected_case_set = set(expected_cases) if expected_cases is not None else None
    observed_cases: set[tuple[str, int]] = set()
    _validate_sequences(records, errors)

    for record in records:
        if record.get("benchmark") != "mldsa":
            errors.append(f"sequence {record.get('sequence')}: benchmark must be mldsa")
        algorithm = record.get("algorithm")
        size = _require_int(record, "message_size_bytes", errors)
        if not isinstance(algorithm, str) or algorithm not in {"ML-DSA-65", "ML-DSA-87"}:
            errors.append(f"sequence {record.get('sequence')}: unexpected ML-DSA algorithm")
            continue
        observed_cases.add((algorithm, size))
        _require_nonnegative_number(record, "sign_time_ns", errors)
        _require_nonnegative_number(record, "verify_time_ns", errors)
        if _require_nonnegative_number(record, "signature_size_bytes", errors) <= 0:
            errors.append(f"sequence {record.get('sequence')}: signature size must be positive")
        if not _require_bool(record, "verification_success", errors):
            errors.append(f"sequence {record.get('sequence')}: ML-DSA verification failed")
        if not _require_bool(record, "negative_self_test_passed", errors):
            errors.append(f"sequence {record.get('sequence')}: ML-DSA negative self-test failed")
        if not _require_bool(record, "success", errors):
            errors.append(f"sequence {record.get('sequence')}: ML-DSA record failed")

    if expected_case_set is not None and observed_cases != expected_case_set:
        errors.append(
            f"missing measured ML-DSA cases: expected {sorted(expected_case_set)}, "
            f"observed {sorted(observed_cases)}"
        )
    if errors:
        raise ValueError("; ".join(errors))
    return errors
