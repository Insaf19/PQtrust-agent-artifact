from __future__ import annotations

from pathlib import Path

import pytest

from pqtrust_agent.crypto.smoke_validation import (
    atomic_write_json,
    create_smoke_summary,
    refuse_nonempty_output_dir,
    verify_checksums,
    write_checksums,
)


def tls_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": 1,
        "benchmark": "tls13_handshake",
        "sequence": 0,
        "block": 0,
        "position_in_block": 0,
        "requested_group": "X25519",
        "negotiated_group": "X25519",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "wall_time_ns": 100,
        "process_cpu_time_ns": 90,
        "client_to_server_bytes": 10,
        "server_to_client_bytes": 20,
        "total_handshake_bytes": 30,
        "certificate_verify_result": 0,
        "session_reused": False,
        "success": True,
        "error_code": 0,
    }
    record.update(overrides)
    return record


def mldsa_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": 1,
        "benchmark": "mldsa",
        "sequence": 0,
        "block": 0,
        "position_in_block": 0,
        "algorithm": "ML-DSA-65",
        "message_size_bytes": 512,
        "sign_time_ns": 100,
        "verify_time_ns": 80,
        "signature_size_bytes": 3309,
        "verification_success": True,
        "negative_self_test_passed": True,
        "success": True,
        "error_code": 0,
    }
    record.update(overrides)
    return record


def test_smoke_count_validation_passes() -> None:
    tls_records = [
        tls_record(sequence=i, requested_group=group, negotiated_group=group)
        for i, group in enumerate(
            [
                "X25519",
                "MLKEM768",
                "X25519",
                "MLKEM768",
                "X25519",
                "MLKEM768",
                "X25519",
                "MLKEM768",
                "X25519",
                "MLKEM768",
            ]
        )
    ]
    mldsa_records = [
        mldsa_record(sequence=i, algorithm=algorithm, message_size_bytes=size)
        for i, (algorithm, size) in enumerate(
            [
                ("ML-DSA-65", 512),
                ("ML-DSA-65", 2048),
                ("ML-DSA-87", 512),
                ("ML-DSA-87", 2048),
            ]
            * 5
        )
    ]
    summary = create_smoke_summary(
        tls_records,
        mldsa_records,
        ["X25519", "MLKEM768"],
        [512, 2048],
        [],
    )
    assert summary["smoke_passed"] is True
    assert summary["expected_record_counts"] == {"tls13_handshake": 10, "mldsa": 20}


def test_checksum_verification(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    atomic_write_json(first, {"kind": "fixture"})
    atomic_write_json(second, {"kind": "fixture2"})
    checksum = write_checksums(tmp_path, [first, second])
    verify_checksums(checksum)
    second.write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_checksums(checksum)


def test_refuse_to_overwrite_outputs(tmp_path: Path) -> None:
    output_dir = tmp_path / "smoke"
    output_dir.mkdir()
    (output_dir / "existing").write_text("data", encoding="utf-8")
    with pytest.raises(FileExistsError):
        refuse_nonempty_output_dir(output_dir)
