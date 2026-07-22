#!/usr/bin/env python3
"""Capture reproducible environment facts for PQTrust-Agent experiments."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TARGET_GROUPS = (
    "X25519",
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "MLKEM768",
    "SecP384r1MLKEM1024",
)

OPENSSL_MINIMUM_VERSION = (3, 5, 0)


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    executable_found: bool


def run_command(command: list[str]) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return CommandResult(command, None, "", "executable not found", False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else "command timed out"
        return CommandResult(command, None, stdout, stderr, True)

    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        executable_found=True,
    )


def parse_openssl_version(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"\bOpenSSL\s+(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def version_at_least(
    version: tuple[int, int, int] | None,
    minimum: tuple[int, int, int],
) -> bool:
    return version is not None and version >= minimum


def command_to_dict(result: CommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "executable_found": result.executable_found,
    }


def parse_tls_group_tokens(groups_output: str) -> set[str]:
    return {token.casefold() for token in re.split(r"[:\s]+", groups_output.strip()) if token}


def detect_target_groups(
    tls_groups_result: CommandResult,
) -> tuple[bool, dict[str, bool | None]]:
    query_supported = tls_groups_result.returncode == 0
    if not query_supported:
        return False, dict.fromkeys(TARGET_GROUPS, None)

    detected_groups = parse_tls_group_tokens(tls_groups_result.stdout)
    available_groups: dict[str, bool | None] = {
        group: group.casefold() in detected_groups
        for group in TARGET_GROUPS
    }
    return True, available_groups


def collect_environment(openssl_bin: str | None = None) -> dict[str, Any]:
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    uname = platform.uname()

    git_result = run_command(["git", "--version"])
    openssl_path = shutil.which("openssl") if openssl_bin is None else shutil.which(openssl_bin)
    openssl_executable = openssl_path or openssl_bin or "openssl"
    openssl_version_result = run_command([openssl_executable, "version", "-a"])
    tls_groups_result = run_command([openssl_executable, "list", "-tls1_3", "-tls-groups"])

    openssl_version = parse_openssl_version(openssl_version_result.stdout)
    version_detection_succeeded = openssl_version is not None
    tls_group_query_supported, available_groups = detect_target_groups(tls_groups_result)
    openssl_at_least_35 = version_at_least(openssl_version, OPENSSL_MINIMUM_VERSION)
    pq_tls_ready = (
        openssl_at_least_35
        and tls_groups_result.returncode == 0
        and all(available is True for available in available_groups.values())
    )

    return {
        "timestamp_utc": timestamp,
        "system": {
            "os": uname.system,
            "kernel": uname.release,
            "kernel_version": uname.version,
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu": uname.processor,
            "platform": platform.platform(),
        },
        "python": {
            "executable": sys.executable,
            "version": sys.version,
            "version_info": {
                "major": sys.version_info.major,
                "minor": sys.version_info.minor,
                "micro": sys.version_info.micro,
            },
        },
        "git": {
            "version": git_result.stdout.strip() if git_result.returncode == 0 else None,
            "command": command_to_dict(git_result),
        },
        "openssl": {
            "executable": openssl_path,
            "selected_executable": openssl_executable,
            "version": ".".join(str(part) for part in openssl_version)
            if openssl_version is not None
            else None,
            "version_tuple": list(openssl_version) if openssl_version is not None else None,
            "version_detection_succeeded": version_detection_succeeded,
            "at_least_3_5": openssl_at_least_35,
            "version_command": command_to_dict(openssl_version_result),
            "tls_group_query_supported": tls_group_query_supported,
            "tls_group_query_command": tls_groups_result.command,
            "tls_group_query_returncode": tls_groups_result.returncode,
            "tls_group_query_unsupported_stderr": tls_groups_result.stderr
            if not tls_group_query_supported
            else None,
            "tls_groups_command": command_to_dict(tls_groups_result),
            "target_groups": available_groups,
            "pq_tls_ready": pq_tls_ready,
        },
    }


def format_report(report: dict[str, Any]) -> str:
    system = report["system"]
    python_info = report["python"]
    git_info = report["git"]
    openssl_info = report["openssl"]

    lines = [
        "PQTrust-Agent Environment Report",
        "================================",
        f"UTC timestamp: {report['timestamp_utc']}",
        "",
        "System",
        f"  OS: {system['os']}",
        f"  Kernel: {system['kernel']}",
        f"  Kernel version: {system['kernel_version']}",
        f"  Architecture: {system['architecture']}",
        f"  Processor: {system['processor'] or system['cpu'] or 'unknown'}",
        f"  Platform: {system['platform']}",
        "",
        "Python",
        f"  Executable: {python_info['executable']}",
        f"  Version: {python_info['version']}",
        "",
        "Git",
        f"  Version: {git_info['version'] or 'unavailable'}",
        "",
        "OpenSSL",
        f"  Selected executable: {openssl_info['selected_executable']}",
        f"  Resolved executable: {openssl_info['executable'] or 'unavailable'}",
        f"  Version: {openssl_info['version'] or 'unavailable'}",
        f"  Version detection succeeded: {openssl_info['version_detection_succeeded']}",
        f"  At least 3.5: {openssl_info['at_least_3_5']}",
        f"  TLS group query supported: {openssl_info['tls_group_query_supported']}",
        f"  TLS group query command: {' '.join(openssl_info['tls_group_query_command'])}",
        f"  TLS group query return code: {openssl_info['tls_group_query_returncode']}",
        "  Target TLS groups:",
    ]

    for group, available in openssl_info["target_groups"].items():
        lines.append(f"    {group}: {available}")

    lines.extend(
        [
            f"  PQ TLS ready: {openssl_info['pq_tls_ready']}",
            "",
            "OpenSSL version -a output",
            "-------------------------",
            openssl_info["version_command"]["stdout"].rstrip() or "(unavailable)",
        ]
    )

    tls_command = openssl_info["tls_groups_command"]
    if openssl_info["tls_group_query_unsupported_stderr"]:
        lines.extend(
            [
                "",
                "OpenSSL TLS groups unsupported stderr",
                "-------------------------------------",
                openssl_info["tls_group_query_unsupported_stderr"].rstrip(),
            ]
        )

    lines.extend(
        [
            "",
            "OpenSSL TLS groups output",
            "-------------------------",
            tls_command["stdout"].rstrip()
            if tls_command["returncode"] == 0
            else tls_command["stderr"].rstrip() or "(unavailable)",
        ]
    )

    return "\n".join(lines) + "\n"


def write_reports(report: dict[str, Any], output_dir: Path) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "environment_report.json"
    text_path = output_dir / "environment_report.txt"
    readable = format_report(report)

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    text_path.write_text(readable, encoding="utf-8")
    return readable


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/environment"),
        help="Directory for environment_report.json and environment_report.txt.",
    )
    parser.add_argument(
        "--openssl-bin",
        default=None,
        help="OpenSSL executable to inspect. Defaults to the executable found through PATH.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report = collect_environment(args.openssl_bin)
    readable = write_reports(report, args.output_dir)
    print(readable, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
