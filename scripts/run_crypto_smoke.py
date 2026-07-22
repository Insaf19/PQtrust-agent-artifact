#!/usr/bin/env python3
"""Run the Stage 3A native crypto functional smoke gate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.material_manifest import ManifestContext, create_material_manifest
from pqtrust_agent.crypto.native_runner import NativeRunner, load_jsonl
from pqtrust_agent.crypto.smoke_validation import (
    atomic_write_json,
    create_smoke_summary,
    refuse_nonempty_output_dir,
    write_checksums,
)
from pqtrust_agent.models.catalog import load_profile_catalog

TLS_GROUPS = [
    "X25519",
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "MLKEM768",
    "SecP384r1MLKEM1024",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/smoke/crypto_smoke"))
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser.parse_args()


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


def _run_validation_script(repo_root: Path, script: str, args: list[str]) -> None:
    completed = subprocess.run(
        ["python3", str(repo_root / "scripts" / script), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{script} failed:\n{completed.stdout}\n{completed.stderr}")


def _copy_json_atomic(source: Path, destination: Path) -> None:
    loaded = _load_json(source)
    atomic_write_json(destination, loaded)


def _repo_rel(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    output_dir = args.output_dir if args.output_dir.is_absolute() else repo_root / args.output_dir
    try:
        _repo_rel(repo_root, output_dir)
    except ValueError as exc:
        raise ValueError(
            "output-dir must be inside the repository for reproducible metadata"
        ) from exc
    refuse_nonempty_output_dir(output_dir)

    environment_report = repo_root / "artifacts/environment/environment_report.json"
    catalog_validation = repo_root / "artifacts/environment/profile_catalog_validation.json"
    catalog_path = repo_root / "configs/profiles/trust_profiles.yaml"
    material_dir = repo_root / ".local/pqtrust-crypto"
    openssl = repo_root / ".local/openssl-3.5.7/bin/openssl"
    tls_binary = repo_root / ".build/native/tls_handshake_bench"
    mldsa_binary = repo_root / ".build/native/mldsa_bench"

    validation_errors: list[str] = []
    environment = _load_json(environment_report)
    if environment.get("openssl", {}).get("pq_tls_ready") is not True:
        validation_errors.append("environment report does not indicate PQ TLS readiness")

    _run_validation_script(
        repo_root,
        "validate_profile_catalog.py",
        [
            "--catalog",
            str(catalog_path),
            "--environment-report",
            str(environment_report),
            "--output",
            str(catalog_validation),
        ],
    )
    catalog_report = _load_json(catalog_validation)
    if catalog_report.get("validation_passed") is not True:
        validation_errors.append("profile catalog validation failed")
    catalog = load_profile_catalog(catalog_path)
    if [profile.tls_group for profile in catalog.profiles] != TLS_GROUPS:
        validation_errors.append("profile catalog TLS groups do not match smoke configuration")

    material_manifest = create_material_manifest(
        ManifestContext(repo_root=repo_root, material_dir=material_dir, openssl_executable=openssl)
    )
    if material_manifest.get("validation_passed") is not True:
        validation_errors.extend(
            str(item) for item in material_manifest.get("validation_errors", [])
        )

    for binary in (tls_binary, mldsa_binary):
        if not binary.is_file():
            validation_errors.append(f"missing native binary: {binary}")
        elif not binary.stat().st_mode & 0o111:
            validation_errors.append(f"native binary is not executable: {binary}")

    if validation_errors:
        atomic_write_json(
            output_dir / "smoke_summary.json",
            {
                "schema_version": 1,
                "validation_errors": validation_errors,
                "smoke_passed": False,
            },
        )
        return 1

    _copy_json_atomic(environment_report, output_dir / "environment_snapshot.json")
    atomic_write_json(output_dir / "catalog_snapshot.json", catalog.model_dump(mode="json"))
    atomic_write_json(output_dir / "material_manifest.json", material_manifest)

    runner = NativeRunner(timeout_seconds=args.timeout_seconds)
    with tempfile.TemporaryDirectory(dir=output_dir, prefix=".stage-") as stage_name:
        stage_dir = Path(stage_name)
        tls_stage_output = stage_dir / "tls_handshakes.jsonl"
        tls_stage_metadata = stage_dir / "tls_batch_metadata.json"
        mldsa_stage_output = stage_dir / "mldsa.jsonl"
        mldsa_stage_metadata = stage_dir / "mldsa_batch_metadata.json"

        tls_command = [
            _repo_rel(repo_root, tls_binary),
            "--groups",
            ",".join(TLS_GROUPS),
            "--certificate",
            _repo_rel(repo_root, material_dir / "server_p256.cert.pem"),
            "--private-key",
            _repo_rel(repo_root, material_dir / "server_p256.key.pem"),
            "--ca-certificate",
            _repo_rel(repo_root, material_dir / "lab_ca_p256.cert.pem"),
            "--warmups",
            "2",
            "--repetitions",
            "5",
            "--seed",
            "20260713",
            "--output",
            _repo_rel(repo_root, tls_stage_output),
        ]
        runner.run(tls_command, tls_stage_output, "tls13_handshake", cwd=repo_root)

        mldsa_command = [
            _repo_rel(repo_root, mldsa_binary),
            "--mldsa65-private",
            _repo_rel(repo_root, material_dir / "mldsa65.private.pem"),
            "--mldsa65-public",
            _repo_rel(repo_root, material_dir / "mldsa65.public.pem"),
            "--mldsa87-private",
            _repo_rel(repo_root, material_dir / "mldsa87.private.pem"),
            "--mldsa87-public",
            _repo_rel(repo_root, material_dir / "mldsa87.public.pem"),
            "--message-sizes",
            "512,2048",
            "--warmups",
            "2",
            "--repetitions",
            "5",
            "--seed",
            "20260714",
            "--output",
            _repo_rel(repo_root, mldsa_stage_output),
        ]
        runner.run(mldsa_command, mldsa_stage_output, "mldsa", cwd=repo_root)

        tls_output = output_dir / "tls_handshakes.jsonl"
        mldsa_output = output_dir / "mldsa.jsonl"
        os.replace(tls_stage_output, tls_output)
        os.replace(tls_stage_metadata, output_dir / "tls_batch_metadata.json")
        os.replace(mldsa_stage_output, mldsa_output)
        os.replace(mldsa_stage_metadata, output_dir / "mldsa_batch_metadata.json")

    tls_records = load_jsonl(tls_output)
    mldsa_records = load_jsonl(mldsa_output)
    summary = create_smoke_summary(tls_records, mldsa_records, TLS_GROUPS, [512, 2048], [])
    atomic_write_json(output_dir / "smoke_summary.json", summary)

    files = [
        output_dir / "environment_snapshot.json",
        output_dir / "catalog_snapshot.json",
        output_dir / "material_manifest.json",
        output_dir / "tls_handshakes.jsonl",
        output_dir / "tls_batch_metadata.json",
        output_dir / "mldsa.jsonl",
        output_dir / "mldsa_batch_metadata.json",
        output_dir / "smoke_summary.json",
    ]
    for path in files:
        if not path.exists():
            raise FileNotFoundError(path)
    write_checksums(output_dir, files)
    return 0 if summary["smoke_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
