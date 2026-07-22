from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pqtrust_agent.crypto.native_runner import (
    NativeExecutionError,
    NativeRunner,
    validate_mldsa_records,
    validate_tls_records,
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


def test_valid_tls_records() -> None:
    validate_tls_records([tls_record()], ["X25519"])


@pytest.mark.parametrize(
    ("requested", "negotiated"),
    [
        ("X25519", "x25519"),
        ("x25519", "X25519"),
    ],
)
def test_tls_group_comparison_is_exact_ascii_case_insensitive(
    requested: str,
    negotiated: str,
) -> None:
    validate_tls_records(
        [tls_record(requested_group=requested, negotiated_group=negotiated)],
        [requested],
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"requested_group": "X25519", "negotiated_group": "X25519MLKEM768"},
        {"negotiated_group": "X25519\u0001"},
        {"negotiated_group": "X25519\udcff"},
        {"negotiated_group": ""},
        {"server_negotiated_group": "MLKEM768"},
    ],
)
def test_tls_group_validation_rejects_malformed_or_different_groups(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        validate_tls_records([tls_record(**overrides)], ["X25519"])


def test_tls_record_validation_reports_exact_group_mismatch() -> None:
    with pytest.raises(ValueError) as exc_info:
        validate_tls_records(
            [tls_record(requested_group="X25519", negotiated_group="MLKEM768")],
            ["X25519"],
        )
    text = str(exc_info.value)
    assert "TLS_GROUP_NEGOTIATION_MISMATCH" in text
    assert "requested_raw': 'X25519'" in text
    assert "negotiated_raw': 'MLKEM768'" in text


@pytest.mark.parametrize(
    "overrides",
    [
        {"negotiated_group": "MLKEM768"},
        {"tls_version": "TLSv1.2"},
        {"session_reused": True},
        {"client_to_server_bytes": 0},
        {"wall_time_ns": -1},
    ],
)
def test_invalid_tls_records_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        validate_tls_records([tls_record(**overrides)], ["X25519"])


def test_duplicate_sequence_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate sequence"):
        validate_tls_records([tls_record(), tls_record()], ["X25519"])


def test_missing_profile_group_rejected() -> None:
    with pytest.raises(ValueError, match="missing measured TLS groups"):
        validate_tls_records([tls_record()], ["X25519", "MLKEM768"])


def test_valid_mldsa_records() -> None:
    validate_mldsa_records([mldsa_record()], [("ML-DSA-65", 512)])


@pytest.mark.parametrize(
    "overrides",
    [
        {"verification_success": False},
        {"negative_self_test_passed": False},
        {"sign_time_ns": -5},
    ],
)
def test_invalid_mldsa_records_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        validate_mldsa_records([mldsa_record(**overrides)], [("ML-DSA-65", 512)])


def test_runner_uses_no_shell_and_preserves_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 7, "", "native stderr evidence")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = NativeRunner(timeout_seconds=1)
    with pytest.raises(NativeExecutionError) as exc_info:
        runner.run(["/tmp/native", "--flag"], tmp_path / "out.jsonl", "tls13_handshake")

    assert captured["kwargs"]  # proves the fake was called
    assert captured["kwargs"]["shell"] is False  # type: ignore[index]
    assert exc_info.value.stderr == "native stderr evidence"


def test_runner_timeout_preserves_stderr(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1, stderr="timeout stderr")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = NativeRunner(timeout_seconds=1)
    with pytest.raises(NativeExecutionError) as exc_info:
        runner.run(["/tmp/native"], tmp_path / "out.jsonl", "mldsa")
    assert "timed out" in str(exc_info.value)
    assert exc_info.value.stderr == "timeout stderr"


def test_runner_validates_written_jsonl(tmp_path: Path) -> None:
    output = tmp_path / "out.jsonl"
    output.write_text(
        '{"schema_version":1,"benchmark":"mldsa","sequence":0,"block":0,'
        '"position_in_block":0,"algorithm":"ML-DSA-65","message_size_bytes":512,'
        '"sign_time_ns":1,"verify_time_ns":1,"signature_size_bytes":1,'
        '"verification_success":true,"negative_self_test_passed":true,'
        '"success":true,"error_code":0}\n',
        encoding="utf-8",
    )
    runner = NativeRunner(timeout_seconds=5)
    result = runner.run(
        [sys.executable, "-c", "import sys; sys.exit(0)"],
        output,
        "mldsa",
    )
    assert len(result.records) == 1
