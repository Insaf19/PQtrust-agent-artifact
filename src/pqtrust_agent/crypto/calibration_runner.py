"""Controlled Stage 3B native calibration execution."""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

import yaml

from pqtrust_agent.crypto.material_manifest import ManifestContext, create_material_manifest
from pqtrust_agent.crypto.native_runner import NativeRunner
from pqtrust_agent.crypto.smoke_validation import (
    atomic_write_json,
    atomic_write_text,
    refuse_nonempty_output_dir,
    sha256_file,
    write_checksums,
)
from pqtrust_agent.metrics.calibration_models import CryptoCalibrationConfig
from pqtrust_agent.metrics.run_manifest import (
    collect_machine_state,
    command_stdout,
    executable_hashes,
    git_commit,
    git_dirty,
    load_json_object,
    repo_relative,
    utc_now,
)
from pqtrust_agent.models.catalog import load_profile_catalog

PINNED_OPENSSL_VERSION = (3, 5, 7)
PINNED_OPENSSL_VERSION_TEXT = ".".join(str(part) for part in PINNED_OPENSSL_VERSION)
OPENSSL_LIBRARY_BASENAMES = frozenset({"libssl.so.3", "libcrypto.so.3"})


def resolve_repo_path(repo_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else repo_root / path


def select_cpu(requested: str, config_cpu: int | None) -> int:
    if hasattr(os, "sched_getaffinity"):
        available = sorted(os.sched_getaffinity(0))
    else:
        available = list(range(os.cpu_count() or 1))
    if not available:
        raise RuntimeError("no available CPU cores")
    if requested == "auto":
        candidate = config_cpu if config_cpu is not None else available[0]
    else:
        candidate = int(requested)
    if candidate not in available:
        raise ValueError(f"CPU core {candidate} is not in current affinity set {available}")
    return candidate


def selected_cpu_from_run(raw_root: Path, run_id: str) -> int:
    manifest_path = raw_root / run_id / "run_manifest.json"
    manifest = load_json_object(manifest_path)
    selected = manifest.get("selected_cpu")
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise ValueError(f"{manifest_path} does not contain an integer selected_cpu")
    return selected


def affinity_command(command: list[str], cpu_core: int) -> list[str]:
    taskset = shutil.which("taskset")
    if taskset is None:
        return command
    return [taskset, "-c", str(cpu_core), *command]


def parse_openssl_version_evidence(text: str | None) -> tuple[tuple[int, int, int], ...] | None:
    if text is None:
        return None
    matches = re.findall(r"(?:\bOpenSSL\s+|\b)(\d+)\.(\d+)\.(\d+)\b", text)
    if not matches:
        return None
    return tuple((int(major), int(minor), int(patch)) for major, minor, patch in matches)


def validate_openssl_executable_and_version(
    openssl: Path, repo_root: Path, version_output: str | None
) -> str | None:
    expected = (repo_root / ".local/openssl-3.5.7/bin/openssl").resolve()
    observed = openssl.resolve()
    if observed != expected:
        return f"OpenSSL executable must resolve to {expected}, observed: {observed}"
    versions = parse_openssl_version_evidence(version_output)
    if versions is None:
        return f"OpenSSL version output is malformed, observed: {version_output}"
    if any(version != PINNED_OPENSSL_VERSION for version in versions):
        observed_versions = ", ".join(
            ".".join(str(part) for part in version) for version in versions
        )
        return (
            f"repository-local OpenSSL {PINNED_OPENSSL_VERSION_TEXT} required, "
            f"observed version(s): {observed_versions}; full output: {version_output}"
        )
    return None


def _ldd_library_paths(output: str) -> dict[str, list[Path | None]]:
    libraries: dict[str, list[Path | None]] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=>" in line:
            name_text, remainder = line.split("=>", maxsplit=1)
            name = Path(name_text.strip()).name
            target_text = remainder.strip().split(maxsplit=1)[0]
            target = None if target_text == "not" else Path(target_text)
        else:
            first = line.split(maxsplit=1)[0]
            name = Path(first).name
            target = Path(first) if first.startswith("/") else None
        if name in OPENSSL_LIBRARY_BASENAMES:
            libraries.setdefault(name, []).append(target)
    return libraries


def _path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def validate_native_linkage(
    binary_name: str,
    ldd_output: str,
    repo_root: Path,
) -> list[str]:
    openssl_prefix = repo_root / ".local/openssl-3.5.7"
    libraries = _ldd_library_paths(ldd_output)
    required = {"libcrypto.so.3"}
    if binary_name == "tls_handshake_bench":
        required.add("libssl.so.3")
    errors: list[str] = []
    for basename in sorted(required):
        resolved = libraries.get(basename, [])
        if not resolved:
            errors.append(f"{binary_name} does not resolve required {basename}")
            continue
        if any(path is None or not _path_is_under(path, openssl_prefix) for path in resolved):
            observed = ", ".join(
                str(path) if path is not None else "not found" for path in resolved
            )
            errors.append(
                f"{binary_name} resolves {basename} outside repository-local OpenSSL: {observed}"
            )
    optional_ssl = libraries.get("libssl.so.3", [])
    if binary_name == "mldsa_bench" and any(
        path is None or not _path_is_under(path, openssl_prefix) for path in optional_ssl
    ):
        observed = ", ".join(
            str(path) if path is not None else "not found" for path in optional_ssl
        )
        errors.append(
            f"{binary_name} resolves optional libssl.so.3 outside repository-local OpenSSL: "
            f"{observed}"
        )
    return errors


def native_uses_local_libraries(
    binary: Path, repo_root: Path, binary_name: str
) -> tuple[bool, str, list[str]]:
    output = command_stdout(["ldd", str(binary)], cwd=repo_root) or ""
    errors = validate_native_linkage(binary_name, output, repo_root)
    return not errors, output, errors


def _stderr_path(replicate_dir: Path, name: str) -> Path:
    path = replicate_dir / "native_stderr" / f"{name}.stderr.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _copy_config_snapshot(path: Path, output: Path) -> None:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    text = yaml.safe_dump(loaded, sort_keys=True)
    atomic_write_text(output, text)


def _validate_inputs(
    repo_root: Path,
    config: CryptoCalibrationConfig,
    allow_dirty: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    openssl = resolve_repo_path(repo_root, config.native_executable_paths.openssl)
    if not openssl.is_file():
        errors.append(f"missing OpenSSL executable: {openssl}")
    version = command_stdout([str(openssl), "version"]) if openssl.exists() else None
    if openssl.exists() and (
        openssl_error := validate_openssl_executable_and_version(openssl, repo_root, version)
    ):
        errors.append(openssl_error)
    if git_dirty(repo_root) and not allow_dirty:
        errors.append("repository is dirty; rerun with --allow-dirty to record a dirty run")

    environment_path = repo_root / "artifacts/environment/environment_report.json"
    catalog_report_path = repo_root / "artifacts/environment/profile_catalog_validation.json"
    smoke_path = repo_root / "artifacts/smoke/crypto_smoke/smoke_summary.json"
    for path in (environment_path, catalog_report_path, smoke_path):
        if not path.is_file():
            errors.append(f"missing required previous-stage artifact: {path}")
    environment = load_json_object(environment_path) if environment_path.is_file() else {}
    if environment.get("openssl", {}).get("version") != "3.5.7":
        errors.append("environment report does not record OpenSSL 3.5.7")
    if environment.get("openssl", {}).get("pq_tls_ready") is not True:
        errors.append("environment report does not record pq_tls_ready=true")
    catalog_report = load_json_object(catalog_report_path) if catalog_report_path.is_file() else {}
    if catalog_report.get("validation_passed") is not True:
        errors.append("profile catalog validation did not pass")
    smoke = load_json_object(smoke_path) if smoke_path.is_file() else {}
    if smoke.get("smoke_passed") is not True:
        errors.append("previous crypto smoke summary does not have smoke_passed=true")
    catalog = load_profile_catalog(repo_root / "configs/profiles/trust_profiles.yaml")
    if tuple(profile.tls_group for profile in catalog.profiles) != config.tls_groups:
        errors.append("profile catalog TLS groups do not match calibration config")

    material_manifest = create_material_manifest(
        ManifestContext(
            repo_root=repo_root,
            material_dir=repo_root / ".local/pqtrust-crypto",
            openssl_executable=openssl,
        )
    )
    if material_manifest.get("validation_passed") is not True:
        errors.extend(str(item) for item in material_manifest.get("validation_errors", []))

    native_paths = {
        "tls_handshake_bench": resolve_repo_path(
            repo_root, config.native_executable_paths.tls_handshake_bench
        ),
        "mldsa_bench": resolve_repo_path(repo_root, config.native_executable_paths.mldsa_bench),
    }
    ldd_outputs: dict[str, str] = {}
    for name, path in native_paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            errors.append(f"missing executable native binary: {path}")
            continue
        ok, ldd_output, linkage_errors = native_uses_local_libraries(path, repo_root, name)
        ldd_outputs[name] = ldd_output
        if not ok:
            errors.extend(linkage_errors)
    loads = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    if loads[0] > config.max_system_load_warning:
        warnings.append(f"one-minute load average {loads[0]} exceeds configured warning threshold")
    return {
        "errors": errors,
        "warnings": warnings,
        "openssl_executable": str(openssl.resolve()) if openssl.exists() else str(openssl),
        "openssl_version_output": version,
        "environment": environment,
        "environment_report_hash": (
            sha256_file(environment_path) if environment_path.is_file() else None
        ),
        "catalog_hash": catalog.catalog_hash(),
        "catalog": catalog.model_dump(mode="json"),
        "material_manifest": material_manifest,
        "material_manifest_hash": validation_hash(material_manifest),
        "native_executable_hashes": executable_hashes(native_paths),
        "ldd_outputs": ldd_outputs,
    }


def validation_hash(payload: object) -> str:
    import hashlib
    import json

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_calibration_campaign(
    *,
    repo_root: Path,
    config_path: Path,
    config: CryptoCalibrationConfig,
    run_id: str,
    output_root: Path,
    cpu_core_argument: str,
    allow_dirty: bool,
) -> Path:
    run_dir = output_root / run_id
    refuse_nonempty_output_dir(run_dir)
    selected_cpu = select_cpu(cpu_core_argument, config.cpu_core)
    validation = _validate_inputs(repo_root, config, allow_dirty)
    if validation["errors"]:
        atomic_write_json(
            run_dir / "validation_report.json",
            {"validation_passed": False, **validation},
        )
        raise RuntimeError(
            "calibration preflight failed:\n"
            + "\n".join(f"- {error}" for error in validation["errors"])
        )

    _copy_config_snapshot(config_path, run_dir / "config_snapshot.yaml")
    atomic_write_json(run_dir / "environment_snapshot.json", validation["environment"])
    atomic_write_json(run_dir / "catalog_snapshot.json", validation["catalog"])
    atomic_write_json(run_dir / "material_manifest.json", validation["material_manifest"])

    openssl = resolve_repo_path(repo_root, config.native_executable_paths.openssl)
    native_paths = {
        "tls_handshake_bench": resolve_repo_path(
            repo_root, config.native_executable_paths.tls_handshake_bench
        ),
        "mldsa_bench": resolve_repo_path(repo_root, config.native_executable_paths.mldsa_bench),
    }
    runner = NativeRunner(timeout_seconds=config.per_process_timeout_seconds)
    start = utc_now()
    generated_files: list[Path] = [
        run_dir / "config_snapshot.yaml",
        run_dir / "environment_snapshot.json",
        run_dir / "catalog_snapshot.json",
        run_dir / "material_manifest.json",
    ]
    affinity_applied = shutil.which("taskset") is not None
    for index, replicate in enumerate(config.replicates, start=1):
        replicate_dir = run_dir / "replicates" / f"replicate-{index:02d}"
        replicate_dir.mkdir(parents=True, exist_ok=True)
        pre_state = collect_machine_state(
            repo_root=repo_root,
            selected_cpu=selected_cpu,
            openssl=openssl,
            native_executables=native_paths,
            config_hash=config.config_hash(),
        )
        atomic_write_json(replicate_dir / "pre_state.json", pre_state)
        generated_files.append(replicate_dir / "pre_state.json")

        tls_output = replicate_dir / "tls_handshakes.jsonl"
        tls_command = [
            repo_relative(repo_root, native_paths["tls_handshake_bench"]),
            "--groups",
            ",".join(config.tls_groups),
            "--certificate",
            config.certificate_paths.server_certificate,
            "--private-key",
            config.certificate_paths.server_private_key,
            "--ca-certificate",
            config.certificate_paths.ca_certificate,
            "--warmups",
            str(config.warmups_per_case),
            "--repetitions",
            str(config.measured_blocks),
            "--seed",
            str(replicate.tls_seed),
            "--output",
            repo_relative(repo_root, tls_output),
        ]
        tls_result = runner.run(
            affinity_command(tls_command, selected_cpu),
            tls_output,
            "tls13_handshake",
            cwd=repo_root,
        )
        atomic_write_text(_stderr_path(replicate_dir, "tls_handshake_bench"), tls_result.stderr)

        mldsa_output = replicate_dir / "mldsa.jsonl"
        mldsa_command = [
            repo_relative(repo_root, native_paths["mldsa_bench"]),
            "--mldsa65-private",
            config.mldsa_key_paths.mldsa65_private,
            "--mldsa65-public",
            config.mldsa_key_paths.mldsa65_public,
            "--mldsa87-private",
            config.mldsa_key_paths.mldsa87_private,
            "--mldsa87-public",
            config.mldsa_key_paths.mldsa87_public,
            "--message-sizes",
            ",".join(str(size) for size in config.mldsa_message_sizes_bytes),
            "--warmups",
            str(config.warmups_per_case),
            "--repetitions",
            str(config.measured_blocks),
            "--seed",
            str(replicate.mldsa_seed),
            "--output",
            repo_relative(repo_root, mldsa_output),
        ]
        mldsa_result = runner.run(
            affinity_command(mldsa_command, selected_cpu),
            mldsa_output,
            "mldsa",
            cwd=repo_root,
        )
        atomic_write_text(_stderr_path(replicate_dir, "mldsa_bench"), mldsa_result.stderr)

        post_state = collect_machine_state(
            repo_root=repo_root,
            selected_cpu=selected_cpu,
            openssl=openssl,
            native_executables=native_paths,
            config_hash=config.config_hash(),
        )
        atomic_write_json(replicate_dir / "post_state.json", post_state)
        generated_files.extend(
            [
                tls_output,
                replicate_dir / "tls_batch_metadata.json",
                mldsa_output,
                replicate_dir / "mldsa_batch_metadata.json",
                _stderr_path(replicate_dir, "tls_handshake_bench"),
                _stderr_path(replicate_dir, "mldsa_bench"),
                replicate_dir / "post_state.json",
            ]
        )
        if index < len(config.replicates):
            time.sleep(config.inter_replicate_idle_seconds)

    completion = utc_now()
    validation_report = {
        "schema_version": 1,
        "validation_passed": True,
        "pre_execution_warnings": validation["warnings"],
        "affinity_applied": affinity_applied,
        "affinity_note": (
            None if affinity_applied else "taskset not available; process affinity not applied"
        ),
    }
    atomic_write_json(run_dir / "validation_report.json", validation_report)
    generated_files.append(run_dir / "validation_report.json")
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "campaign_id": config.campaign_id,
        "calibration_configuration_hash": config.config_hash(),
        "exact_configuration_hash": config.exact_configuration_hash(),
        "scientific_design_hash": config.scientific_design_hash(),
        "catalog_hash": validation["catalog_hash"],
        "environment_report_hash": validation["environment_report_hash"],
        "material_manifest_hash": validation["material_manifest_hash"],
        "openssl_version": command_stdout([str(openssl), "version"]),
        "git_commit": git_commit(repo_root),
        "git_dirty": git_dirty(repo_root),
        "selected_cpu": selected_cpu,
        "replicate_count": len(config.replicates),
        "expected_tls_record_count": config.expected_tls_records_total(),
        "expected_mldsa_record_count": config.expected_mldsa_records_total(),
        "start_timestamp_utc": start,
        "completion_timestamp_utc": completion,
        "completion_status": "completed",
        "raw_file_inventory": sorted(
            path.relative_to(run_dir).as_posix() for path in generated_files
        ),
    }
    atomic_write_json(run_dir / "run_manifest.json", manifest)
    generated_files.append(run_dir / "run_manifest.json")
    write_checksums(run_dir, sorted(generated_files))
    return run_dir
