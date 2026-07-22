"""Run-manifest and machine-state helpers for calibration evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.smoke_validation import atomic_write_json, atomic_write_text, sha256_file


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_relative(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def load_json_object(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


def git_commit(repo_root: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def git_dirty(repo_root: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    return result.returncode != 0 or bool(result.stdout.strip())


def executable_hashes(paths: dict[str, Path]) -> dict[str, str | None]:
    return {name: sha256_file(path) if path.is_file() else None for name, path in paths.items()}


def command_stdout(command: list[str], *, cwd: Path | None = None, timeout: int = 30) -> str | None:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def file_sha256_hex(path: Path) -> str:
    return sha256_file(path)


def object_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_optional_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _read_mem_available_kb() -> int | None:
    meminfo = _read_optional_text(Path("/proc/meminfo"))
    if meminfo is None:
        return None
    for line in meminfo.splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1])
    return None


def _cpu_model() -> str | None:
    cpuinfo = _read_optional_text(Path("/proc/cpuinfo"))
    if cpuinfo is None:
        return platform.processor() or None
    for line in cpuinfo.splitlines():
        if line.startswith("model name"):
            return line.split(":", maxsplit=1)[1].strip()
    return platform.processor() or None


def scaling_state(cpu: int | None) -> dict[str, str | None]:
    if cpu is None:
        return {"governor": None, "scaling_cur_freq": None}
    base = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    return {
        "governor": _read_optional_text(base / "scaling_governor"),
        "scaling_cur_freq": _read_optional_text(base / "scaling_cur_freq"),
    }


def thermal_temperatures() -> dict[str, int | None]:
    base = Path("/sys/class/thermal")
    if not base.exists():
        return {}
    temperatures: dict[str, int | None] = {}
    for zone in sorted(base.glob("thermal_zone*")):
        temperatures[zone.name] = (
            int(value) if (value := _read_optional_text(zone / "temp")) is not None else None
        )
    return temperatures


def process_affinity() -> list[int] | None:
    getter = getattr(os, "sched_getaffinity", None)
    if getter is None:
        return None
    return sorted(int(cpu) for cpu in getter(0))


def collect_machine_state(
    *,
    repo_root: Path,
    selected_cpu: int | None,
    openssl: Path,
    native_executables: dict[str, Path],
    config_hash: str,
) -> dict[str, Any]:
    scaling = scaling_state(selected_cpu)
    return {
        "timestamp_utc": utc_now(),
        "monotonic_timestamp": time.monotonic(),
        "selected_cpu": selected_cpu,
        "process_affinity": process_affinity(),
        "logical_cpu_count": os.cpu_count(),
        "load_averages": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        "available_memory_kb": _read_mem_available_kb(),
        "cpu_model": _cpu_model(),
        "kernel": platform.release(),
        "openssl_runtime_version": command_stdout([str(openssl), "version"]),
        "native_executable_hashes": executable_hashes(native_executables),
        "cpu_scaling_governor": scaling["governor"],
        "cpu_scaling_frequency": scaling["scaling_cur_freq"],
        "thermal_zone_temperatures": thermal_temperatures(),
        "python_version": sys.version,
        "git_commit": git_commit(repo_root),
        "git_dirty": git_dirty(repo_root),
        "configuration_hash": config_hash,
    }


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_json(path, payload)


def write_text_atomic(path: Path, text: str) -> None:
    atomic_write_text(path, text)
