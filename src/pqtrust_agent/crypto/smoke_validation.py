"""Validation helpers for Stage 3A crypto smoke artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.native_runner import validate_mldsa_records, validate_tls_records


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def refuse_nonempty_output_dir(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(output_dir: Path, files: list[Path]) -> Path:
    checksum_path = output_dir / "checksums.sha256"
    lines = []
    for file_path in files:
        rel = file_path.relative_to(output_dir).as_posix()
        lines.append(f"{sha256_file(file_path)}  {rel}")
    atomic_write_text(checksum_path, "\n".join(lines) + "\n")
    verify_checksums(checksum_path)
    return checksum_path


def verify_checksums(checksum_path: Path) -> None:
    base = checksum_path.parent
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel.strip()
        path = base / rel
        if sha256_file(path) != digest:
            raise ValueError(f"checksum mismatch for {rel}")


def create_smoke_summary(
    tls_records: list[dict[str, Any]],
    mldsa_records: list[dict[str, Any]],
    requested_groups: list[str],
    message_sizes: list[int],
    validation_errors: list[str],
) -> dict[str, Any]:
    expected_tls = len(requested_groups) * 5
    expected_mldsa = 2 * len(message_sizes) * 5
    try:
        validate_tls_records(tls_records, requested_groups)
        validate_mldsa_records(
            mldsa_records,
            [
                (algorithm, size)
                for algorithm in ("ML-DSA-65", "ML-DSA-87")
                for size in message_sizes
            ],
        )
    except ValueError as exc:
        validation_errors.append(str(exc))

    return {
        "schema_version": 1,
        "expected_record_counts": {"tls13_handshake": expected_tls, "mldsa": expected_mldsa},
        "observed_record_counts": {
            "tls13_handshake": len(tls_records),
            "mldsa": len(mldsa_records),
        },
        "successful_record_counts": {
            "tls13_handshake": sum(1 for record in tls_records if record.get("success") is True),
            "mldsa": sum(1 for record in mldsa_records if record.get("success") is True),
        },
        "requested_groups": requested_groups,
        "negotiated_groups": sorted(
            {record["negotiated_group"] for record in tls_records if "negotiated_group" in record}
        ),
        "mldsa_algorithms": sorted(
            {record["algorithm"] for record in mldsa_records if "algorithm" in record}
        ),
        "message_sizes": message_sizes,
        "validation_errors": validation_errors,
        "smoke_passed": not validation_errors
        and len(tls_records) == expected_tls
        and len(mldsa_records) == expected_mldsa,
    }
