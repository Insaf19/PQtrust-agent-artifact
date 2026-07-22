"""Stage 8 final campaign registration, raw inventory, and validation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from pqtrust_agent.campaigns.stage8_measurement import (
    MeasurementError,
    measure_dispatch,
    unavailable,
    validate_observation_row,
    warm_up_tls_groups,
)
from pqtrust_agent.evidence.canonical import canonicalize, domain_separated_sha256
from pqtrust_agent.runtime.stage7_evidence import ADVERSARIAL_CASES, PROFILE_GROUP, load_json
from pqtrust_agent.tls_groups import require_matching_tls_groups

CONFIG_PATH = Path("configs/campaigns/stage8_final_campaign.yaml")
REGISTRATION_DIR = Path("artifacts/campaigns/registration")
FINAL_DIR = Path("artifacts/campaigns/final")
RUNS_DIR = Path("runs/stage8")

FEASIBLE_JSONL = "feasible_sessions.jsonl"
INFEASIBLE_JSONL = "infeasible_sessions.jsonl"
ADVERSARIAL_JSONL = "adversarial_trials.jsonl"
CONCURRENCY_JSONL = "concurrency_trials.jsonl"
COMPONENT_JSONL = "component_trials.jsonl"
RAW_FILES = (
    FEASIBLE_JSONL,
    INFEASIBLE_JSONL,
    ADVERSARIAL_JSONL,
    CONCURRENCY_JSONL,
    COMPONENT_JSONL,
)
EXPECTED = {
    "feasible": 480,
    "infeasible": 150,
    "adversarial": 200,
    "concurrency": 100,
    "component": 110,
}
REQUIRED_STAGE_HASH_KEYS = ("stage5", "stage6", "stage7", "stage7_bundle_validation")
REGISTRATION_FILES = (
    "registered_design.json",
    "environment_preflight.json",
    "execution_schedule.json",
    "checksums.sha256",
)


class Stage8Error(RuntimeError):
    """Raised when Stage 8 registration or validation fails."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load_yaml_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise Stage8Error(f"expected mapping in {path}")
    return cast(dict[str, Any], loaded)


def canonical_hash(value: Mapping[str, Any]) -> str:
    return domain_separated_sha256("PQTrust.Stage8.CampaignConfig.v1", value)


def git_commit(repo: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def git_dirty(repo: Path) -> bool:
    return bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True))


def _check_file_hash(repo: Path, spec: Mapping[str, Any], label: str) -> list[str]:
    path = repo / str(spec["path"])
    expected = str(spec["sha256"])
    if not path.exists():
        return [f"{label} missing: {path}"]
    observed = sha256_file(path)
    if observed != expected:
        return [f"{label} hash mismatch: expected {expected}, observed {observed}"]
    return []


def verify_registered_inputs(repo: Path, config: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if "repository_commit" in config:
        errors.append("static campaign YAML must not contain repository_commit")
    errors.extend(
        _check_file_hash(repo, cast(Mapping[str, Any], config["catalog_hash"]), "catalog")
    )
    errors.extend(
        _check_file_hash(
            repo,
            cast(Mapping[str, Any], config["paired_cost_evidence_hash"]),
            "paired-cost evidence",
        )
    )
    stage_hashes = cast(Mapping[str, Any], config["stage_bundle_hashes"])
    for key in REQUIRED_STAGE_HASH_KEYS:
        errors.extend(_check_file_hash(repo, cast(Mapping[str, Any], stage_hashes[key]), key))
    return errors


def preflight_environment(
    repo: Path, config: Mapping[str, Any], *, registration_commit: str | None = None
) -> dict[str, Any]:
    openssl_spec = cast(Mapping[str, Any], config["openssl"])
    openssl_path = repo / str(openssl_spec["path"])
    native = [
        {"path": path, "exists": (repo / path).exists()}
        for path in cast(Sequence[str], config["host_environment_requirements"]["native_binaries"])
    ]
    openssl_output: str | None = None
    if openssl_path.exists():
        openssl_output = subprocess.check_output([str(openssl_path), "version"], text=True).strip()
    errors: list[str] = []
    if not openssl_path.exists():
        errors.append("repository-local OpenSSL is unavailable")
    elif str(openssl_spec["version"]) not in str(openssl_output):
        errors.append("repository-local OpenSSL version differs from registration")
    for item in native:
        if not item["exists"]:
            errors.append(f"required native binary missing: {item['path']}")
    errors.extend(verify_registered_inputs(repo, config))
    return {
        "artifact": "stage8_environment_preflight",
        "registration_commit": registration_commit,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "openssl_path": str(openssl_path),
        "openssl_version_output": openssl_output,
        "native_binaries": native,
        "validation_errors": errors,
        "validation_passed": not errors,
    }


def deterministic_schedule(config: Mapping[str, Any]) -> dict[str, Any]:
    seed = int(config["deterministic_ordering_seed"])
    rng = random.Random(seed)
    methods = list(cast(Sequence[str], config["methods"]))
    feasible = list(cast(Sequence[str], config["scenarios"]["feasible"]))
    infeasible = list(cast(Sequence[str], config["scenarios"]["infeasible"]))
    concurrency_scenarios = list(cast(Sequence[str], config["scenarios"]["concurrency"]))
    levels = list(cast(Sequence[int], config["concurrency_levels"]))
    components = list(cast(Sequence[str], config["components"]))
    reps = cast(Mapping[str, int], config["repetitions"])
    block = cast(Mapping[str, int], config["block_design"])
    observations: list[dict[str, Any]] = []

    order = 0
    for block_id in range(1, int(block["feasible_blocks"]) + 1):
        for rep_in_block in range(1, int(block["feasible_repetitions_per_block"]) + 1):
            for scenario in feasible:
                method_order = methods[:]
                rng.shuffle(method_order)
                paired_id = f"pair:{scenario}:b{block_id:02d}:r{rep_in_block:02d}"
                repetition = (
                    (block_id - 1) * int(block["feasible_repetitions_per_block"]) + rep_in_block
                )
                for method in method_order:
                    observations.append(
                        {
                            "order": order,
                            "kind": "feasible",
                            "observation_id": (
                                f"feasible:{scenario}:{method}:b{block_id:02d}:r{repetition:02d}"
                            ),
                            "scenario_id": scenario,
                            "method": method,
                            "block_id": block_id,
                            "repetition": repetition,
                            "paired_comparison_id": paired_id,
                        }
                    )
                    order += 1
    for repetition in range(1, int(reps["infeasible_per_scenario"]) + 1):
        for scenario in infeasible:
            observations.append(
                {
                    "order": order,
                    "kind": "infeasible",
                    "observation_id": f"infeasible:{scenario}:r{repetition:02d}",
                    "scenario_id": scenario,
                    "repetition": repetition,
                }
            )
            order += 1
    for trial in range(1, int(reps["adversarial_trials_per_attack"]) + 1):
        for case in ADVERSARIAL_CASES:
            attack_id = str(case["case_id"])
            observations.append(
                {
                    "order": order,
                    "kind": "adversarial",
                    "observation_id": f"adversarial:{attack_id}:t{trial:02d}",
                    "attack_id": attack_id,
                    "trial": trial,
                }
            )
            order += 1
    for repetition in range(1, int(reps["concurrency_per_scenario_level"]) + 1):
        for scenario in concurrency_scenarios:
            for level in levels:
                observations.append(
                    {
                        "order": order,
                        "kind": "concurrency",
                        "observation_id": f"concurrency:{scenario}:c{level}:r{repetition:02d}",
                        "scenario_id": scenario,
                        "requested_concurrency": level,
                        "repetition": repetition,
                    }
                )
                order += 1
    for process_index in range(1, int(reps["component_processes"]) + 1):
        for component in components:
            observations.append(
                {
                    "order": order,
                    "kind": "component",
                    "observation_id": f"component:{component}:p{process_index:02d}",
                    "component": component,
                    "process_index": process_index,
                    "operations": int(reps["component_operations_per_process"]),
                }
            )
            order += 1
    schedule: dict[str, Any] = {
        "artifact": "stage8_execution_schedule",
        "campaign_id": config["campaign_id"],
        "campaign_version": config["campaign_version"],
        "seed": seed,
        "observation_count": len(observations),
        "observations": observations,
    }
    schedule["schedule_hash"] = domain_separated_sha256(
        "PQTrust.Stage8.ExecutionSchedule.v1", observations
    )
    return schedule


def build_registered_design(repo: Path, config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    config = load_yaml_config(config_path)
    if "repository_commit" in config:
        raise Stage8Error("static campaign YAML must not contain repository_commit")
    registration_commit = git_commit(repo)
    return build_registered_design_from_config(config, config_path, registration_commit)


def build_registered_design_from_config(
    config: Mapping[str, Any], config_path: Path, registration_commit: str
) -> dict[str, Any]:
    config_bytes = canonicalize(config)
    return {
        "artifact": "stage8_registered_design",
        "config_path": config_path.as_posix(),
        "campaign_design_hash": canonical_hash(config),
        "configuration_canonical_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "configuration": config,
        "registration_commit": registration_commit,
    }


def registration_artifact_hash(
    design: Mapping[str, Any], preflight: Mapping[str, Any], schedule: Mapping[str, Any]
) -> str:
    return domain_separated_sha256(
        "PQTrust.Stage8.RegistrationArtifact.v1",
        {
            "campaign_design_hash": design["campaign_design_hash"],
            "registration_commit": design["registration_commit"],
            "registered_design": design,
            "environment_preflight": preflight,
            "execution_schedule": schedule,
        },
    )


def _registration_has_measured_run_started(runs_dir: Path | None = None) -> bool:
    resolved_runs_dir = runs_dir or RUNS_DIR
    if not resolved_runs_dir.exists():
        return False
    return any(path.stat().st_size > 0 for path in resolved_runs_dir.glob("*/raw/*.jsonl"))


def _atomic_replace_registration(
    staging_dir: Path, output_dir: Path, *, replace_existing: bool
) -> None:
    if output_dir.exists() and not replace_existing:
        raise Stage8Error(f"registration already exists: {output_dir}")
    backup_dir = output_dir.with_name(f".{output_dir.name}.replaced")
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    try:
        if output_dir.exists():
            os.replace(output_dir, backup_dir)
        os.replace(staging_dir, output_dir)
    except BaseException:
        if output_dir.exists() and output_dir != staging_dir:
            shutil.rmtree(output_dir)
        if backup_dir.exists():
            os.replace(backup_dir, output_dir)
        raise
    finally:
        if backup_dir.exists():
            shutil.rmtree(backup_dir)


def write_registration(
    repo: Path, *, output_dir: Path | None = None, replace_existing: bool = False
) -> dict[str, Any]:
    resolved_output_dir = output_dir or REGISTRATION_DIR
    config = load_yaml_config()
    if "repository_commit" in config:
        raise Stage8Error("static campaign YAML must not contain repository_commit")
    if git_dirty(repo):
        raise Stage8Error("refusing Stage 8 registration with a dirty Git worktree")
    if replace_existing and _registration_has_measured_run_started():
        raise Stage8Error(
            "refusing to replace Stage 8 registration after a measured run has started"
        )
    registration_commit = git_commit(repo)
    preflight = preflight_environment(repo, config, registration_commit=registration_commit)
    if not preflight["validation_passed"]:
        raise Stage8Error("; ".join(cast(list[str], preflight["validation_errors"])))
    design = build_registered_design_from_config(config, CONFIG_PATH, registration_commit)
    schedule = deterministic_schedule(config)
    artifact_hash = registration_artifact_hash(design, preflight, schedule)
    design["registration_artifact_hash"] = artifact_hash
    preflight["registration_artifact_hash"] = artifact_hash
    staging_dir = resolved_output_dir.with_name(f".{resolved_output_dir.name}.staging")
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)
    try:
        write_json(staging_dir / "registered_design.json", design)
        write_json(staging_dir / "environment_preflight.json", preflight)
        write_json(staging_dir / "execution_schedule.json", schedule)
        write_checksums(staging_dir)
        _atomic_replace_registration(
            staging_dir, resolved_output_dir, replace_existing=replace_existing
        )
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
    return {"registered_design": design, "environment_preflight": preflight, "schedule": schedule}


def load_registration(
    registration_dir: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved_registration_dir = registration_dir or REGISTRATION_DIR
    design = load_json(resolved_registration_dir / "registered_design.json")
    schedule = load_json(resolved_registration_dir / "execution_schedule.json")
    return design, schedule


def expected_run_id(design: Mapping[str, Any], schedule: Mapping[str, Any]) -> str:
    seed = (
        f"{design['campaign_design_hash']}:"
        f"{design['registration_commit']}:"
        f"{schedule['schedule_hash']}"
    )
    return "stage8-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def _raw_path(run_dir: Path, kind: str) -> Path:
    mapping = {
        "feasible": FEASIBLE_JSONL,
        "infeasible": INFEASIBLE_JSONL,
        "adversarial": ADVERSARIAL_JSONL,
        "concurrency": CONCURRENCY_JSONL,
        "component": COMPONENT_JSONL,
    }
    return run_dir / "raw" / mapping[kind]


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                loaded = json.loads(line)
                if not isinstance(loaded, dict):
                    raise Stage8Error(f"JSONL row is not an object: {path}")
                yield cast(dict[str, Any], loaded)


def completed_observation_ids(run_dir: Path) -> set[str]:
    ids: set[str] = set()
    for name in RAW_FILES:
        for row in iter_jsonl(run_dir / "raw" / name):
            observation_id = str(row["observation_id"])
            if observation_id in ids:
                raise Stage8Error(f"duplicate observation ID: {observation_id}")
            ids.add(observation_id)
    return ids


def append_observation(run_dir: Path, kind: str, row: Mapping[str, Any]) -> None:
    canonical_row = validate_observation_row(row)
    path = _raw_path(run_dir, kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    observation_id = str(canonical_row["observation_id"])
    if observation_id in completed_observation_ids(run_dir):
        raise Stage8Error(f"refusing to rewrite completed observation: {observation_id}")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(canonical_row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    _write_completed_index(run_dir)


def _write_completed_index(run_dir: Path) -> None:
    ids = sorted(completed_observation_ids(run_dir))
    write_json(
        run_dir / "raw" / "completed_observations.json",
        {"completed_observation_count": len(ids), "completed_observation_ids": ids},
    )


def prepare_run_dir(repo: Path, run_id: str | None = None) -> Path:
    design, schedule = load_registration()
    _require_registered_commit(repo, design, action="Stage 8 campaign execution")
    design_hash = str(design["campaign_design_hash"])
    current_hash = canonical_hash(load_yaml_config())
    if current_hash != design_hash:
        raise Stage8Error("registered configuration hash differs from current configuration")
    config = cast(Mapping[str, Any], design["configuration"])
    preflight = preflight_environment(
        repo, config, registration_commit=str(design["registration_commit"])
    )
    if not preflight["validation_passed"]:
        raise Stage8Error("; ".join(cast(list[str], preflight["validation_errors"])))
    resolved_run_id = run_id or expected_run_id(design, schedule)
    run_dir = RUNS_DIR / resolved_run_id
    if run_dir.exists() and (run_dir / "RUN_COMPLETE").exists():
        raise Stage8Error(f"output run ID already exists and is complete: {resolved_run_id}")
    if not run_dir.exists():
        (run_dir / "raw").mkdir(parents=True)
        (run_dir / "logs").mkdir()
        (run_dir / "integrity").mkdir()
        for name in RAW_FILES:
            (run_dir / "raw" / name).touch()
        write_json(
            run_dir / "manifest.json",
            {
                "artifact": "stage8_run_manifest",
                "campaign_run_id": resolved_run_id,
                "campaign_design_hash": design_hash,
                "registration_commit": design["registration_commit"],
                "registration_artifact_hash": design["registration_artifact_hash"],
                "schedule_hash": schedule["schedule_hash"],
            },
        )
        write_json(run_dir / "environment.json", preflight)
        write_json(run_dir / "registered_design.json", design)
        write_json(run_dir / "execution_schedule.json", schedule)
        _write_completed_index(run_dir)
    else:
        manifest = load_json(run_dir / "manifest.json")
        checks = {
            "campaign_design_hash": design_hash,
            "registration_commit": str(design["registration_commit"]),
            "registration_artifact_hash": str(design["registration_artifact_hash"]),
            "schedule_hash": str(schedule["schedule_hash"]),
        }
        for key, expected in checks.items():
            if str(manifest.get(key)) != expected:
                raise Stage8Error(f"cannot resume run created under different {key}")
    return run_dir


def _timed_stub() -> tuple[int, int]:
    start = time.perf_counter_ns()
    end = time.perf_counter_ns()
    return start, max(1, end - start)


ObservationMeasurer = Callable[[Path, Path, Mapping[str, Any]], dict[str, Any]]


def measure_observation(repo: Path, run_dir: Path, scheduled: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return measure_dispatch(
            repo,
            run_dir,
            scheduled,
            adversarial_cases=ADVERSARIAL_CASES,
        )
    except MeasurementError as exc:
        raise Stage8Error(str(exc)) from exc


def synthetic_observation_for_tests(
    repo: Path, run_dir: Path, scheduled: Mapping[str, Any]
) -> dict[str, Any]:
    del repo
    manifest = load_json(run_dir / "manifest.json")
    kind = str(scheduled["kind"])
    _, elapsed = _timed_stub()
    base: dict[str, Any] = {
        "observation_id": scheduled["observation_id"],
        "campaign_id": "stage8-final-campaign",
        "run_id": manifest["campaign_run_id"],
        "campaign_design_hash": manifest["campaign_design_hash"],
        "registration_commit": manifest["registration_commit"],
        "classification": None,
    }
    if kind == "feasible":
        profile = "P0" if scheduled["scenario_id"] != "low-risk-quantum-ready-tool" else "P3"
        group = PROFILE_GROUP[profile]
        return base | {
            **scheduled,
            "completed": True,
            "final_state": "COMPLETED",
            "validation_passed": True,
            "failure_phase": None,
            "failure_code": None,
            "selected_profile": profile,
            "requested_tls_group": group,
            "negotiated_tls_group": group,
            "OpenSSL_version": "OpenSSL 3.5.7 repository-local",
            "fallback_attempted": False,
            "weaker_retry_attempted": False,
            "resumption_used": False,
            "timing_ns": {"total_session_wall_time": elapsed},
            "resources": {"process_cpu_time_ns": unavailable("not collected by stub harness")},
            "communication": {
                "tls_handshake_bytes": unavailable("native instrumentation required")
            },
            "crypto_counts": {
                "SHA-256_operations": unavailable("protocol instrumentation required")
            },
        }
    if kind == "infeasible":
        return base | {
            **scheduled,
            "total_abort_latency_ns": elapsed,
            "policy_compilation_latency_ns": unavailable("not collected by stub harness"),
            "feasibility_check_latency_ns": unavailable("not collected by stub harness"),
            "initial_Z3_core_size": unavailable("not collected by stub harness"),
            "final_IUS_size": unavailable("not collected by stub harness"),
            "IUS_shrinking_solver_call_count": unavailable("not collected by stub harness"),
            "certificate_construction_latency_ns": unavailable("not collected by stub harness"),
            "certificate_verification_latency_ns": unavailable("not collected by stub harness"),
            "failure_transcript_latency_ns": unavailable("not collected by stub harness"),
            "abort_record_latency_ns": unavailable("not collected by stub harness"),
            "certificate_serialized_size": unavailable("not collected by stub harness"),
            "failure_transcript_size": unavailable("not collected by stub harness"),
            "abort_record_size": unavailable("not collected by stub harness"),
            "remediation_report_size": unavailable("not collected by stub harness"),
            "final_category": scheduled["scenario_id"],
            "final_state": "ABORTED",
            "TLS_invoked": False,
            "task_invoked": False,
            "fallback_attempted": False,
        }
    if kind == "adversarial":
        case = next(case for case in ADVERSARIAL_CASES if case["case_id"] == scheduled["attack_id"])
        expected = str(case["code"])
        return base | {
            **scheduled,
            "target_phase": case["target_phase"],
            "mutation": case["mutation_description"],
            "expected_rejection_code": expected,
            "observed_rejection_code": expected,
            "rejected": True,
            "fail_closed": True,
            "rejection_latency_ns": elapsed,
            "runtime_state_at_rejection": case["state"],
            "TLS_invoked": bool(case.get("tls")),
            "task_invoked": False,
            "weaker_retry_attempted": False,
        }
    if kind == "concurrency":
        level = int(scheduled["requested_concurrency"])
        return base | {
            **scheduled,
            "successful_sessions": level,
            "failed_sessions": 0,
            "aggregate_throughput": level,
            "median_session_latency_ns": elapsed,
            "p95_session_latency_ns": elapsed,
            "maximum_session_latency_ns": elapsed,
            "total_process_cpu_time_ns": unavailable("not collected by stub harness"),
            "peak_total_RSS": unavailable("not collected by stub harness"),
            "socket_or_transport_failures": 0,
            "timeout_count": 0,
            "selected_profile_distribution": {"P0": level},
            "negotiated_group_distribution": {"X25519": level},
        }
    if kind == "component":
        return base | {
            **scheduled,
            "batch_latency_ns": elapsed,
            "operation_count": scheduled["operations"],
            "completed": True,
        }
    raise Stage8Error(f"unknown schedule kind: {kind}")


def run_campaign(
    repo: Path,
    *,
    run_id: str | None = None,
    resume: bool = False,
    measurer: ObservationMeasurer = measure_observation,
) -> Path:
    run_dir = prepare_run_dir(repo, run_id)
    if (run_dir / "RUN_COMPLETE").exists():
        raise Stage8Error("run is already complete")
    design, schedule = load_registration()
    if measurer is measure_observation:
        _ensure_warmups(repo, run_dir, cast(Mapping[str, Any], design["configuration"]))
    done = completed_observation_ids(run_dir) if resume else set()
    observations = cast(list[dict[str, Any]], schedule["observations"])
    total = len(observations)
    failures = 0
    started = time.perf_counter()
    for scheduled in observations:
        if str(scheduled["observation_id"]) in done:
            continue
        row = measurer(repo, run_dir, scheduled)
        append_observation(run_dir, str(scheduled["kind"]), row)
        if row.get("classification") is not None:
            failures += 1
        completed = len(completed_observation_ids(run_dir))
        _write_progress_snapshot(
            run_dir,
            completed=completed,
            total=total,
            scheduled=scheduled,
            elapsed_seconds=time.perf_counter() - started,
            failures=failures,
        )
    finalize_run(run_dir, repo=repo)
    return run_dir


def _ensure_warmups(repo: Path, run_dir: Path, config: Mapping[str, Any]) -> None:
    manifest_path = run_dir / "manifest.json"
    manifest = load_json(manifest_path)
    if manifest.get("tls_warmup_completed") is True:
        return
    groups = list(cast(Mapping[str, Any], config["warmup"])["tls_groups"])
    warmup = warm_up_tls_groups(repo, [str(group) for group in groups])
    write_json(manifest_path, manifest | {"warmup": warmup, "tls_warmup_completed": True})


def _write_progress_snapshot(
    run_dir: Path,
    *,
    completed: int,
    total: int,
    scheduled: Mapping[str, Any],
    elapsed_seconds: float,
    failures: int,
) -> None:
    payload = {
        "completed": completed,
        "total": total,
        "observation_type": scheduled.get("kind"),
        "scenario": scheduled.get("scenario_id"),
        "component": scheduled.get("component"),
        "method": scheduled.get("method"),
        "block": scheduled.get("block_id"),
        "repetition": scheduled.get("repetition"),
        "elapsed_seconds": elapsed_seconds,
        "failures_so_far": failures,
    }
    write_json(run_dir / "progress.json", payload)
    print(
        json.dumps(
            {
                "completed": completed,
                "total": total,
                "type": payload["observation_type"],
                "scenario": payload["scenario"],
                "component": payload["component"],
                "method": payload["method"],
                "block": payload["block"],
                "repetition": payload["repetition"],
                "elapsed_seconds": round(elapsed_seconds, 3),
                "failures": failures,
            },
            sort_keys=True,
        ),
        flush=True,
    )


def write_checksums(root: Path) -> None:
    lines: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "checksums.sha256"):
        lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    (root / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_checksums(root: Path) -> list[str]:
    checksum_path = root / "checksums.sha256"
    if not checksum_path.exists():
        return [f"missing checksum file: {checksum_path}"]
    expected: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if line:
            digest, rel = line.split(maxsplit=1)
            expected[rel.strip()] = digest
    errors: list[str] = []
    for rel, digest in expected.items():
        path = root / rel
        if not path.exists():
            errors.append(f"checksummed file missing: {rel}")
        elif sha256_file(path) != digest:
            errors.append(f"checksum mismatch: {rel}")
    return errors


def finalize_run(run_dir: Path, *, repo: Path | None = None) -> None:
    validation = validate_run(run_dir, write_report=False, repo=repo)
    if not validation["validation_passed"]:
        raise Stage8Error("; ".join(cast(list[str], validation["validation_errors"])))
    write_checksums(run_dir / "raw")
    raw_checksum_errors = verify_checksums(run_dir / "raw")
    if raw_checksum_errors:
        raise Stage8Error("; ".join(raw_checksum_errors))
    write_file_manifest(run_dir)
    write_checksums(run_dir / "integrity")
    integrity_errors = verify_checksums(run_dir / "integrity")
    if integrity_errors:
        raise Stage8Error("; ".join(integrity_errors))
    tmp = run_dir / ".RUN_COMPLETE.tmp"
    tmp.write_text("complete\n", encoding="utf-8")
    os.replace(tmp, run_dir / "RUN_COMPLETE")


def write_file_manifest(run_dir: Path) -> None:
    files = []
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file() and "integrity" not in p.parts):
        files.append(
            {
                "path": path.relative_to(run_dir).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    write_json(run_dir / "integrity" / "file_manifest.json", {"files": files})


def count_raw(run_dir: Path) -> dict[str, int]:
    return {
        "feasible": sum(1 for _ in iter_jsonl(run_dir / "raw" / FEASIBLE_JSONL)),
        "infeasible": sum(1 for _ in iter_jsonl(run_dir / "raw" / INFEASIBLE_JSONL)),
        "adversarial": sum(1 for _ in iter_jsonl(run_dir / "raw" / ADVERSARIAL_JSONL)),
        "concurrency": sum(1 for _ in iter_jsonl(run_dir / "raw" / CONCURRENCY_JSONL)),
        "component": sum(1 for _ in iter_jsonl(run_dir / "raw" / COMPONENT_JSONL)),
    }


def _require_registered_commit(repo: Path, design: Mapping[str, Any], *, action: str) -> None:
    if git_dirty(repo):
        raise Stage8Error(f"refusing {action} with a dirty Git worktree")
    current_commit = git_commit(repo)
    registered_commit = str(design["registration_commit"])
    if current_commit != registered_commit:
        raise Stage8Error("repository commit differs from registration_commit")


def validate_run(
    run_dir: Path, *, write_report: bool = True, repo: Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    design = load_json(run_dir / "registered_design.json")
    if repo is not None:
        _require_registered_commit(repo, design, action="Stage 8 campaign validation")
    schedule = load_json(run_dir / "execution_schedule.json")
    scheduled_ids = [str(item["observation_id"]) for item in schedule["observations"]]
    rows_by_id: dict[str, dict[str, Any]] = {}
    for name in RAW_FILES:
        for row in iter_jsonl(run_dir / "raw" / name):
            observation_id = str(row["observation_id"])
            if observation_id in rows_by_id:
                errors.append(f"duplicate observation ID: {observation_id}")
            try:
                validate_observation_row(row)
            except Exception as exc:
                errors.append(f"schema validation failed for {observation_id}: {exc}")
            rows_by_id[observation_id] = row
    missing = sorted(set(scheduled_ids) - set(rows_by_id))
    extra = sorted(set(rows_by_id) - set(scheduled_ids))
    if missing:
        errors.append(f"missing observations: {len(missing)}")
    if extra:
        errors.append(f"unscheduled observations: {len(extra)}")
    counts = count_raw(run_dir)
    for key, expected in EXPECTED.items():
        if counts[key] != expected:
            errors.append(f"{key} count mismatch: expected {expected}, observed {counts[key]}")
    errors.extend(_validate_feasible(run_dir))
    errors.extend(_validate_infeasible(run_dir))
    errors.extend(_validate_adversarial(run_dir))
    errors.extend(_validate_concurrency(run_dir))
    errors.extend(_validate_block_balance(schedule, rows_by_id))
    if (run_dir / "raw" / "checksums.sha256").exists():
        errors.extend(verify_checksums(run_dir / "raw"))
    if (run_dir / "integrity" / "checksums.sha256").exists():
        errors.extend(verify_checksums(run_dir / "integrity"))
    current_hash = canonical_hash(load_yaml_config())
    if current_hash != str(design["campaign_design_hash"]):
        errors.append("registered design changes detected")
    report: dict[str, Any] = {
        "artifact": "stage8_campaign_validation",
        "run_dir": run_dir.as_posix(),
        "expected_counts": EXPECTED,
        "observed_counts": counts,
        "validation_errors": errors,
        "validation_passed": not errors,
    }
    if write_report:
        write_json(FINAL_DIR / "campaign_validation.json", report)
    return report


def _validate_feasible(run_dir: Path) -> list[str]:
    errors: list[str] = []
    for row in iter_jsonl(run_dir / "raw" / FEASIBLE_JSONL):
        if not row.get("completed") or row.get("final_state") != "COMPLETED":
            errors.append(f"unexpected feasible-session failure: {row['observation_id']}")
        try:
            require_matching_tls_groups(
                requested=str(row.get("requested_tls_group")),
                negotiated=str(row.get("negotiated_tls_group")),
            )
        except ValueError as exc:
            errors.append(f"TLS group mismatch: {row['observation_id']}: {exc}")
        if row.get("fallback_attempted") or row.get("weaker_retry_attempted"):
            errors.append(f"forbidden fallback/retry: {row['observation_id']}")
    return errors


def _validate_infeasible(run_dir: Path) -> list[str]:
    errors: list[str] = []
    categories: dict[str, set[str]] = defaultdict(set)
    for row in iter_jsonl(run_dir / "raw" / INFEASIBLE_JSONL):
        if row.get("TLS_invoked") or row.get("task_invoked") or row.get("fallback_attempted"):
            errors.append(f"infeasible safety invariant failed: {row['observation_id']}")
        if row.get("final_state") != "ABORTED":
            errors.append(f"infeasible final state is not ABORTED: {row['observation_id']}")
        categories[str(row["scenario_id"])].add(str(row["final_category"]))
    for scenario, values in categories.items():
        if len(values) != 1:
            errors.append(f"infeasible category is nondeterministic for {scenario}")
    return errors


def _validate_adversarial(run_dir: Path) -> list[str]:
    errors: list[str] = []
    for row in iter_jsonl(run_dir / "raw" / ADVERSARIAL_JSONL):
        if not row.get("rejected") or not row.get("fail_closed"):
            errors.append(f"attack accepted or did not fail closed: {row['observation_id']}")
        if row.get("expected_rejection_code") != row.get("observed_rejection_code"):
            errors.append(f"attack rejection code mismatch: {row['observation_id']}")
        if row.get("task_invoked") or row.get("weaker_retry_attempted"):
            errors.append(f"attack safety invariant failed: {row['observation_id']}")
    return errors


def _validate_concurrency(run_dir: Path) -> list[str]:
    errors: list[str] = []
    for row in iter_jsonl(run_dir / "raw" / CONCURRENCY_JSONL):
        if int(row["requested_concurrency"]) > 16:
            errors.append(f"oversubscribed concurrency: {row['observation_id']}")
        if int(row["successful_sessions"]) + int(row["failed_sessions"]) != int(
            row["requested_concurrency"]
        ):
            errors.append(f"concurrency aggregate mismatch: {row['observation_id']}")
    return errors


def _validate_block_balance(
    schedule: Mapping[str, Any], rows_by_id: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    expected = Counter(
        (item["scenario_id"], item["block_id"], item["method"])
        for item in cast(list[dict[str, Any]], schedule["observations"])
        if item["kind"] == "feasible"
    )
    observed = Counter(
        (row["scenario_id"], row["block_id"], row["method"])
        for row in rows_by_id.values()
        if row.get("kind") == "feasible"
    )
    return ["feasible block balance mismatch"] if expected != observed else []


def analyze_inventory(
    run_dir: Path, *, output_dir: Path | None = None, repo: Path | None = None
) -> dict[str, Any]:
    resolved_output_dir = output_dir or FINAL_DIR
    validation = validate_run(run_dir, write_report=False, repo=repo)
    if not validation["validation_passed"]:
        raise Stage8Error("cannot derive final inventory from invalid raw run")
    resolved_output_dir.mkdir(parents=True, exist_ok=True)
    write_json(resolved_output_dir / "campaign_validation.json", validation)
    inventory = {"artifact": "stage8_sample_inventory", "counts": count_raw(run_dir)}
    write_json(resolved_output_dir / "sample_inventory.json", inventory)
    _write_summary_csv(
        resolved_output_dir / "feasible_summary.csv", run_dir / "raw" / FEASIBLE_JSONL
    )
    _write_summary_csv(
        resolved_output_dir / "infeasible_summary.csv", run_dir / "raw" / INFEASIBLE_JSONL
    )
    _write_summary_csv(
        resolved_output_dir / "adversarial_summary.csv", run_dir / "raw" / ADVERSARIAL_JSONL
    )
    _write_summary_csv(
        resolved_output_dir / "concurrency_summary.csv", run_dir / "raw" / CONCURRENCY_JSONL
    )
    _write_summary_csv(
        resolved_output_dir / "component_summary.csv", run_dir / "raw" / COMPONENT_JSONL
    )
    failures = [
        row
        for name in RAW_FILES
        for row in iter_jsonl(run_dir / "raw" / name)
        if row.get("classification") is not None or row.get("failed_sessions", 0)
    ]
    write_json(resolved_output_dir / "failure_inventory.json", {"failures": failures})
    shutil.copyfile(run_dir / "environment.json", resolved_output_dir / "environment.json")
    design = load_json(run_dir / "registered_design.json")
    provenance = {
        "artifact": "stage8_provenance",
        "campaign_design_hash": design["campaign_design_hash"],
        "registration_commit": design["registration_commit"],
        "registration_artifact_hash": design["registration_artifact_hash"],
        "run_manifest_hash": sha256_file(run_dir / "manifest.json"),
        "registered_design_hash": sha256_file(run_dir / "registered_design.json"),
        "execution_schedule_hash": sha256_file(run_dir / "execution_schedule.json"),
    }
    write_json(resolved_output_dir / "provenance.json", provenance)
    write_checksums(resolved_output_dir)
    return inventory


def _write_summary_csv(output_path: Path, raw_path: Path) -> None:
    rows = list(iter_jsonl(raw_path))
    fields = ["observation_id", "kind", "scenario_id", "method", "attack_id", "component"]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, default=Path.cwd())


def register_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register the immutable Stage 8 campaign design.")
    add_common_args(parser)
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args(argv)
    result = write_registration(args.repo, replace_existing=bool(args.replace_existing))
    print(
        json.dumps(
            {
                "campaign_design_hash": result["registered_design"]["campaign_design_hash"],
                "registration_commit": result["registered_design"]["registration_commit"],
                "registration_artifact_hash": result["registered_design"][
                    "registration_artifact_hash"
                ],
            }
        )
    )
    return 0


def run_main(argv: Sequence[str] | None = None, *, resume: bool = False) -> int:
    parser = argparse.ArgumentParser(description="Execute the registered Stage 8 campaign.")
    add_common_args(parser)
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    run_dir = run_campaign(args.repo, run_id=args.run_id, resume=resume)
    print(json.dumps({"run_dir": run_dir.as_posix()}))
    return 0


def analyze_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Stage 8 raw-to-derived inventory.")
    add_common_args(parser)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args(argv)
    analyze_inventory(args.run_dir, repo=args.repo)
    print(json.dumps({"output_dir": FINAL_DIR.as_posix()}))
    return 0


def validate_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a completed Stage 8 campaign run.")
    add_common_args(parser)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args(argv)
    result = validate_run(args.run_dir, repo=args.repo)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation_passed"] else 1
