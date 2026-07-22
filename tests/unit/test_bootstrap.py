from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pqtrust_agent

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_package_importable() -> None:
    assert pqtrust_agent.__name__ == "pqtrust_agent"


def test_version_string_exists() -> None:
    assert isinstance(pqtrust_agent.__version__, str)
    assert pqtrust_agent.__version__ == "0.1.0"


def test_expected_main_directories_exist() -> None:
    expected = [
        "configs",
        "schemas",
        "src/pqtrust_agent",
        "tests",
        "experiments",
        "scripts",
        "specs/tla",
        "docs",
        "artifacts/environment",
        "runs/raw",
        "runs/processed",
        "paper",
    ]

    missing = [path for path in expected if not (REPO_ROOT / path).is_dir()]

    assert missing == []


def test_environment_checker_writes_valid_json(tmp_path: Path) -> None:
    output_dir = tmp_path / "environment"
    script = REPO_ROOT / "scripts" / "check_environment.py"

    completed = subprocess.run(
        [sys.executable, str(script), "--output-dir", str(output_dir)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "PQTrust-Agent Environment Report" in completed.stdout

    report_path = output_dir / "environment_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert "timestamp_utc" in report
    assert "openssl" in report
    assert isinstance(report["openssl"]["target_groups"], dict)
    assert isinstance(report["openssl"]["pq_tls_ready"], bool)


def make_fake_openssl(
    tmp_path: Path,
    *,
    version: str,
    groups: list[str] | None,
    group_separator: str = "\n",
    unsupported_stderr: str = "list: Unknown option: -tls-groups",
) -> Path:
    fake_openssl = tmp_path / f"openssl-{version.replace('.', '-')}"
    groups_literal = repr(groups)
    group_separator_literal = repr(group_separator)
    fake_openssl.write_text(
        f"""#!/usr/bin/env python3
from __future__ import annotations

import sys

VERSION = {version!r}
GROUPS = {groups_literal}
GROUP_SEPARATOR = {group_separator_literal}
UNSUPPORTED_STDERR = {unsupported_stderr!r}

if sys.argv[1:] == ["version", "-a"]:
    print(f"OpenSSL {{VERSION}} 1 Jul 2026")
    raise SystemExit(0)

if sys.argv[1:] == ["list", "-tls1_3", "-tls-groups"]:
    if GROUPS is None:
        print(UNSUPPORTED_STDERR, file=sys.stderr)
        raise SystemExit(1)
    print(GROUP_SEPARATOR.join(GROUPS))
    raise SystemExit(0)

print("unexpected fake openssl arguments: " + " ".join(sys.argv[1:]), file=sys.stderr)
raise SystemExit(2)
""",
        encoding="utf-8",
    )
    fake_openssl.chmod(0o755)
    return fake_openssl


def run_environment_checker(tmp_path: Path, openssl_bin: Path) -> dict[str, object]:
    output_dir = tmp_path / "environment"
    script = REPO_ROOT / "scripts" / "check_environment.py"

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--output-dir",
            str(output_dir),
            "--openssl-bin",
            str(openssl_bin),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    return json.loads((output_dir / "environment_report.json").read_text(encoding="utf-8"))


def test_environment_checker_detects_supported_openssl_35_groups(tmp_path: Path) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "X25519",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
        ],
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert openssl["selected_executable"] == str(fake_openssl)
    assert openssl["version_detection_succeeded"] is True
    assert openssl["tls_group_query_supported"] is True
    assert openssl["tls_group_query_command"] == [
        str(fake_openssl),
        "list",
        "-tls1_3",
        "-tls-groups",
    ]
    assert openssl["tls_group_query_returncode"] == 0
    assert openssl["tls_group_query_unsupported_stderr"] is None
    assert openssl["target_groups"] == {
        "X25519": True,
        "X25519MLKEM768": True,
        "SecP256r1MLKEM768": True,
        "MLKEM768": False,
        "SecP384r1MLKEM1024": True,
    }
    assert openssl["pq_tls_ready"] is False


def test_environment_checker_reports_null_groups_for_unsupported_query(tmp_path: Path) -> None:
    fake_openssl = make_fake_openssl(tmp_path, version="3.0.13", groups=None)

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert openssl["version"] == "3.0.13"
    assert openssl["tls_group_query_supported"] is False
    assert openssl["tls_group_query_returncode"] == 1
    assert openssl["tls_group_query_unsupported_stderr"] == "list: Unknown option: -tls-groups\n"
    assert openssl["target_groups"] == {
        "X25519": None,
        "X25519MLKEM768": None,
        "SecP256r1MLKEM768": None,
        "MLKEM768": None,
        "SecP384r1MLKEM1024": None,
    }
    assert openssl["pq_tls_ready"] is False


def test_environment_checker_sets_pq_tls_ready_when_all_requirements_pass(tmp_path: Path) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "X25519",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "MLKEM768",
            "SecP384r1MLKEM1024",
        ],
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert openssl["target_groups"] == {
        "X25519": True,
        "X25519MLKEM768": True,
        "SecP256r1MLKEM768": True,
        "MLKEM768": True,
        "SecP384r1MLKEM1024": True,
    }
    assert openssl["pq_tls_ready"] is True


def test_environment_checker_detects_observed_lowercase_x25519_output(
    tmp_path: Path,
) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "x25519",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "MLKEM768",
            "SecP384r1MLKEM1024",
        ],
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert openssl["target_groups"] == {
        "X25519": True,
        "X25519MLKEM768": True,
        "SecP256r1MLKEM768": True,
        "MLKEM768": True,
        "SecP384r1MLKEM1024": True,
    }
    assert openssl["pq_tls_ready"] is True


def test_environment_checker_detects_uppercase_and_mixed_case_groups(
    tmp_path: Path,
) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "X25519",
            "x25519MlKeM768",
            "sECp256R1mlkem768",
            "mlkem768",
            "SECP384R1MLKEM1024",
        ],
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert openssl["target_groups"] == {
        "X25519": True,
        "X25519MLKEM768": True,
        "SecP256r1MLKEM768": True,
        "MLKEM768": True,
        "SecP384r1MLKEM1024": True,
    }
    assert openssl["pq_tls_ready"] is True


def test_environment_checker_detects_colon_separated_groups(tmp_path: Path) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "X25519",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "MLKEM768",
            "SecP384r1MLKEM1024",
        ],
        group_separator=":",
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert all(openssl["target_groups"].values())
    assert openssl["pq_tls_ready"] is True


def test_environment_checker_detects_whitespace_separated_groups(tmp_path: Path) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "X25519",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "MLKEM768",
            "SecP384r1MLKEM1024",
        ],
        group_separator=" ",
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert all(openssl["target_groups"].values())
    assert openssl["pq_tls_ready"] is True


def test_environment_checker_does_not_use_substring_group_matches(tmp_path: Path) -> None:
    fake_openssl = make_fake_openssl(
        tmp_path,
        version="3.5.7",
        groups=[
            "X25519Extra",
            "X25519MLKEM768Extra",
            "SecP256r1MLKEM768Extra",
            "PreMLKEM768",
            "SecP384r1MLKEM1024Extra",
        ],
    )

    report = run_environment_checker(tmp_path, fake_openssl)
    openssl = report["openssl"]

    assert isinstance(openssl, dict)
    assert openssl["target_groups"] == {
        "X25519": False,
        "X25519MLKEM768": False,
        "SecP256r1MLKEM768": False,
        "MLKEM768": False,
        "SecP384r1MLKEM1024": False,
    }
    assert openssl["pq_tls_ready"] is False
