from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.crypto import calibration_runner
from pqtrust_agent.crypto.calibration_runner import (
    _validate_inputs,
    parse_openssl_version_evidence,
    validate_native_linkage,
    validate_openssl_executable_and_version,
)
from pqtrust_agent.crypto.smoke_validation import atomic_write_json, atomic_write_text
from pqtrust_agent.metrics.calibration_models import load_calibration_config
from pqtrust_agent.metrics.validation import validate_raw_run

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCAL_SSL = ".local/openssl-3.5.7/lib/libssl.so.3"
LOCAL_CRYPTO = ".local/openssl-3.5.7/lib/libcrypto.so.3"


def test_checksum_failures_are_reported(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    atomic_write_text(run_dir / "run_manifest.json", "{}\n")
    atomic_write_text(run_dir / "checksums.sha256", "0" * 64 + "  run_manifest.json\n")
    config = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")

    report = validate_raw_run(run_dir, config)

    assert report["validation_passed"] is False
    assert any("checksum" in error for error in report["errors"])


def test_parse_observed_openssl_357_string() -> None:
    observed = "OpenSSL 3.5.7 9 Jun 2026\n(Library: OpenSSL 3.5.7 9 Jun 2026)"

    assert parse_openssl_version_evidence(observed) == ((3, 5, 7), (3, 5, 7))


@pytest.mark.parametrize("version", ["3.5.6", "3.6.0"])
def test_openssl_validation_rejects_unpinned_versions(tmp_path: Path, version: str) -> None:
    openssl = tmp_path / ".local/openssl-3.5.7/bin/openssl"
    openssl.parent.mkdir(parents=True)
    openssl.write_text("#!/bin/sh\n", encoding="utf-8")

    error = validate_openssl_executable_and_version(
        openssl,
        tmp_path,
        f"OpenSSL {version} 9 Jun 2026\n(Library: OpenSSL {version} 9 Jun 2026)",
    )

    assert error is not None
    assert "3.5.7 required" in error


def test_tls_binary_with_local_ssl_and_crypto_is_accepted(tmp_path: Path) -> None:
    output = "\n".join(
        [
            f"libssl.so.3 => {tmp_path / LOCAL_SSL} (0x0001)",
            f"libcrypto.so.3 => {tmp_path / LOCAL_CRYPTO} (0x0002)",
        ]
    )

    assert validate_native_linkage("tls_handshake_bench", output, tmp_path) == []


def test_tls_binary_with_system_ssl_is_rejected(tmp_path: Path) -> None:
    output = "\n".join(
        [
            "libssl.so.3 => /usr/lib/x86_64-linux-gnu/libssl.so.3 (0x0001)",
            f"libcrypto.so.3 => {tmp_path / LOCAL_CRYPTO} (0x0002)",
        ]
    )

    errors = validate_native_linkage("tls_handshake_bench", output, tmp_path)

    assert any("libssl.so.3 outside repository-local OpenSSL" in error for error in errors)


def test_mldsa_binary_with_local_crypto_only_is_accepted(tmp_path: Path) -> None:
    output = f"libcrypto.so.3 => {tmp_path / LOCAL_CRYPTO} (0x0002)"

    assert validate_native_linkage("mldsa_bench", output, tmp_path) == []


def test_mldsa_binary_with_system_crypto_is_rejected(tmp_path: Path) -> None:
    output = "libcrypto.so.3 => /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (0x0002)"

    errors = validate_native_linkage("mldsa_bench", output, tmp_path)

    assert any("libcrypto.so.3 outside repository-local OpenSSL" in error for error in errors)


def test_mixed_local_system_resolution_is_rejected(tmp_path: Path) -> None:
    output = "\n".join(
        [
            f"libssl.so.3 => {tmp_path / LOCAL_SSL} (0x0001)",
            "libcrypto.so.3 => /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (0x0002)",
        ]
    )

    errors = validate_native_linkage("tls_handshake_bench", output, tmp_path)

    assert any("libcrypto.so.3 outside repository-local OpenSSL" in error for error in errors)


class _Profile:
    def __init__(self, tls_group: str) -> None:
        self.tls_group = tls_group


class _Catalog:
    def __init__(self, tls_groups: tuple[str, ...]) -> None:
        self.profiles = [_Profile(group) for group in tls_groups]

    def catalog_hash(self) -> str:
        return "catalog-hash"

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        return {"mode": mode}


def _prepare_preflight_repo(tmp_path: Path) -> None:
    for relative in (
        ".local/openssl-3.5.7/bin/openssl",
        ".build/native/tls_handshake_bench",
        ".build/native/mldsa_bench",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
    atomic_write_json(
        tmp_path / "artifacts/environment/environment_report.json",
        {"openssl": {"version": "3.5.7", "pq_tls_ready": True}},
    )
    atomic_write_json(
        tmp_path / "artifacts/environment/profile_catalog_validation.json",
        {"validation_passed": True},
    )
    atomic_write_json(
        tmp_path / "artifacts/smoke/crypto_smoke/smoke_summary.json",
        {"smoke_passed": True},
    )


def _patch_successful_preflight(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")

    def command_stdout(command: list[str], **_kwargs: object) -> str | None:
        if command[:1] == ["ldd"]:
            if command[1].endswith("tls_handshake_bench"):
                return "\n".join(
                    [
                        f"libssl.so.3 => {tmp_path / LOCAL_SSL} (0x0001)",
                        f"libcrypto.so.3 => {tmp_path / LOCAL_CRYPTO} (0x0002)",
                    ]
                )
            if command[1].endswith("mldsa_bench"):
                return f"libcrypto.so.3 => {tmp_path / LOCAL_CRYPTO} (0x0002)"
        if command[1:] == ["version"]:
            return "OpenSSL 3.5.7 9 Jun 2026\n(Library: OpenSSL 3.5.7 9 Jun 2026)"
        return None

    monkeypatch.setattr(calibration_runner, "command_stdout", command_stdout)
    monkeypatch.setattr(
        calibration_runner,
        "create_material_manifest",
        lambda _context: {"validation_passed": True},
    )
    monkeypatch.setattr(
        calibration_runner,
        "load_profile_catalog",
        lambda _path: _Catalog(config.tls_groups),
    )


def test_dirty_repository_rejected_unless_allow_dirty_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_preflight_repo(tmp_path)
    _patch_successful_preflight(monkeypatch, tmp_path)
    monkeypatch.setattr(calibration_runner, "git_dirty", lambda _repo: True)
    config = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")

    rejected = _validate_inputs(tmp_path, config, allow_dirty=False)
    accepted = _validate_inputs(tmp_path, config, allow_dirty=True)

    assert any("repository is dirty" in error for error in rejected["errors"])
    assert accepted["errors"] == []


def test_clean_repository_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prepare_preflight_repo(tmp_path)
    _patch_successful_preflight(monkeypatch, tmp_path)
    monkeypatch.setattr(calibration_runner, "git_dirty", lambda _repo: False)
    config = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")

    validation = _validate_inputs(tmp_path, config, allow_dirty=False)

    assert validation["errors"] == []
