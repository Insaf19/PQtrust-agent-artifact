"""Laboratory cryptographic material manifest creation and validation."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MATERIAL_FILES = {
    "ca_certificate": "lab_ca_p256.cert.pem",
    "server_certificate": "server_p256.cert.pem",
    "server_private_key": "server_p256.key.pem",
    "mldsa65_private": "mldsa65.private.pem",
    "mldsa65_public": "mldsa65.public.pem",
    "mldsa87_private": "mldsa87.private.pem",
    "mldsa87_public": "mldsa87.public.pem",
}


@dataclass(frozen=True)
class ManifestContext:
    repo_root: Path
    material_dir: Path
    openssl_executable: Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_relative(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def run_openssl(openssl: Path, args: list[str], *, input_bytes: bytes | None = None) -> str:
    completed = subprocess.run(
        [str(openssl), *args],
        input=input_bytes,
        check=False,
        capture_output=True,
        text=False,
        timeout=30,
        shell=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")
        raise ValueError(f"openssl {' '.join(args)} failed: {stderr}")
    return completed.stdout.decode("utf-8", errors="replace")


def _x509_field(openssl: Path, cert: Path, option: str) -> str:
    output = run_openssl(openssl, ["x509", "-in", str(cert), "-noout", option])
    return output.strip().split("=", maxsplit=1)[-1]


def _certificate_san(openssl: Path, cert: Path) -> list[str]:
    output = run_openssl(openssl, ["x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"])
    values: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("DNS:") or stripped.startswith("IP Address:"):
            values.extend(item.strip() for item in stripped.split(","))
    return values


def _certificate_public_key_algorithm(openssl: Path, cert: Path) -> str:
    output = run_openssl(openssl, ["x509", "-in", str(cert), "-noout", "-text"])
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Public Key Algorithm:"):
            return stripped.split(":", maxsplit=1)[1].strip()
    return "unknown"


def _public_hash(openssl: Path, key: Path, private_key: bool) -> str:
    args = ["pkey", "-in", str(key), "-pubout"]
    if not private_key:
        args = ["pkey", "-pubin", "-in", str(key), "-pubout"]
    pem = run_openssl(openssl, args)
    return hashlib.sha256(pem.encode("utf-8")).hexdigest()


def validate_material(context: ManifestContext) -> list[str]:
    errors: list[str] = []
    paths = {name: context.material_dir / rel for name, rel in MATERIAL_FILES.items()}
    for name, path in paths.items():
        if not path.is_file():
            errors.append(f"missing {name}: {path}")
    if errors:
        return errors
    try:
        run_openssl(
            context.openssl_executable,
            [
                "verify",
                "-CAfile",
                str(paths["ca_certificate"]),
                str(paths["server_certificate"]),
            ],
        )
        san = _certificate_san(context.openssl_executable, paths["server_certificate"])
        if "DNS:localhost" not in san:
            errors.append("server certificate SAN is missing DNS:localhost")
        if "IP Address:127.0.0.1" not in san:
            errors.append("server certificate SAN is missing IP Address:127.0.0.1")
        for name in ("mldsa65_private", "mldsa87_private"):
            run_openssl(context.openssl_executable, ["pkey", "-in", str(paths[name]), "-noout"])
        for name in ("mldsa65_public", "mldsa87_public"):
            run_openssl(
                context.openssl_executable,
                ["pkey", "-pubin", "-in", str(paths[name]), "-noout"],
            )
    except Exception as exc:
        errors.append(str(exc))
    return errors


def create_material_manifest(context: ManifestContext) -> dict[str, Any]:
    paths = {name: context.material_dir / rel for name, rel in MATERIAL_FILES.items()}
    errors = validate_material(context)
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    version = ""
    try:
        version = run_openssl(context.openssl_executable, ["version"]).strip()
    except Exception as exc:
        errors.append(str(exc))

    server_cert = paths["server_certificate"]
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "laboratory_only": True,
        "timestamp_utc": timestamp,
        "openssl_executable": repo_relative(context.repo_root, context.openssl_executable),
        "openssl_executable_absolute": str(context.openssl_executable.resolve()),
        "openssl_version": version,
        "material_directory": repo_relative(context.repo_root, context.material_dir),
        "files": {
            name: {
                "path": repo_relative(context.repo_root, path),
                "sha256": sha256_file(path) if path.exists() else None,
            }
            for name, path in paths.items()
        },
        "validation_passed": not errors,
        "validation_errors": errors,
    }
    if server_cert.exists():
        manifest["x509"] = {
            "server_subject": _x509_field(context.openssl_executable, server_cert, "-subject"),
            "server_issuer": _x509_field(context.openssl_executable, server_cert, "-issuer"),
            "server_serial": _x509_field(context.openssl_executable, server_cert, "-serial"),
            "server_not_before": _x509_field(context.openssl_executable, server_cert, "-startdate"),
            "server_not_after": _x509_field(context.openssl_executable, server_cert, "-enddate"),
            "server_san": _certificate_san(context.openssl_executable, server_cert),
            "server_public_key_algorithm": _certificate_public_key_algorithm(
                context.openssl_executable,
                server_cert,
            ),
        }
    manifest["mldsa"] = {
        "algorithms": ["ML-DSA-65", "ML-DSA-87"],
        "public_key_hashes": {
            "ML-DSA-65": _public_hash(context.openssl_executable, paths["mldsa65_public"], False)
            if paths["mldsa65_public"].exists()
            else None,
            "ML-DSA-87": _public_hash(context.openssl_executable, paths["mldsa87_public"], False)
            if paths["mldsa87_public"].exists()
            else None,
        },
        "private_key_file_hashes": {
            "ML-DSA-65": sha256_file(paths["mldsa65_private"])
            if paths["mldsa65_private"].exists()
            else None,
            "ML-DSA-87": sha256_file(paths["mldsa87_private"])
            if paths["mldsa87_private"].exists()
            else None,
        },
    }
    return manifest


def write_manifest(manifest: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
