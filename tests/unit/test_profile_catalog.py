from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pqtrust_agent.exceptions import CatalogValidationError
from pqtrust_agent.models import ThreatClass
from pqtrust_agent.models.catalog import load_profile_catalog

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPO_ROOT / "configs" / "profiles" / "trust_profiles.yaml"
OBSERVED_GROUP_STRING = (
    "secp256r1:secp384r1:secp521r1:x25519:x448:"
    "brainpoolP256r1tls13:brainpoolP384r1tls13:"
    "brainpoolP512r1tls13:ffdhe2048:ffdhe3072:ffdhe4096:"
    "ffdhe6144:ffdhe8192:MLKEM512:MLKEM768:MLKEM1024:"
    "SecP256r1MLKEM768:X25519MLKEM768:SecP384r1MLKEM1024"
)


def test_catalog_has_exactly_p0_to_p4() -> None:
    catalog = load_profile_catalog(CATALOG_PATH)

    assert catalog.profile_ids() == ("P0", "P1", "P2", "P3", "P4")
    assert tuple(profile.tls_group for profile in catalog.profiles) == (
        "X25519",
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "MLKEM768",
        "SecP384r1MLKEM1024",
    )
    assert catalog.get_profile("P4").assurance.key_establishment_threats == frozenset(
        {ThreatClass.CLASSICAL, ThreatClass.QUANTUM}
    )


def test_catalog_hash_is_stable() -> None:
    first = load_profile_catalog(CATALOG_PATH)
    second = load_profile_catalog(CATALOG_PATH)

    assert first.catalog_hash() == second.catalog_hash()
    assert len(first.catalog_hash()) == 64


def test_catalog_hash_is_stable_across_processes() -> None:
    command = (
        "from pathlib import Path; "
        "from pqtrust_agent.models.catalog import load_profile_catalog; "
        f"print(load_profile_catalog(Path({str(CATALOG_PATH)!r})).catalog_hash())"
    )
    hashes = [
        subprocess.run(
            [sys.executable, "-c", command],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        for _ in range(2)
    ]

    assert hashes[0] == hashes[1]


def test_duplicate_profile_ids_are_rejected(tmp_path: Path) -> None:
    text = CATALOG_PATH.read_text(encoding="utf-8").replace("profile_id: P1", "profile_id: P0", 1)
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(CatalogValidationError):
        load_profile_catalog(path)


def test_duplicate_tls_groups_are_rejected(tmp_path: Path) -> None:
    text = CATALOG_PATH.read_text(encoding="utf-8").replace(
        "tls_group: X25519MLKEM768",
        "tls_group: X25519",
        1,
    )
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(CatalogValidationError):
        load_profile_catalog(path)


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(
        "catalog_version: '1.0'\ncatalog_version: '1.0'\nprofiles: []\n",
        encoding="utf-8",
    )

    with pytest.raises(CatalogValidationError):
        load_profile_catalog(path)


def test_unknown_yaml_fields_are_rejected(tmp_path: Path) -> None:
    text = CATALOG_PATH.read_text(encoding="utf-8").replace(
        "profile_id: P0",
        "profile_id: P0\n    unknown_field: true",
        1,
    )
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(CatalogValidationError):
        load_profile_catalog(path)


def test_observed_openssl_group_output_validates_all_profiles(tmp_path: Path) -> None:
    observed_groups = {item.casefold() for item in OBSERVED_GROUP_STRING.split(":")}
    environment = {
        "openssl": {
            "selected_executable": "/tmp/openssl",
            "version": "3.5.7",
            "version_tuple": [3, 5, 7],
            "pq_tls_ready": True,
            "target_groups": {
                group: group.casefold() in observed_groups
                for group in (
                    "X25519",
                    "X25519MLKEM768",
                    "SecP256r1MLKEM768",
                    "MLKEM768",
                    "SecP384r1MLKEM1024",
                )
            },
        }
    }
    environment_path = tmp_path / "environment_report.json"
    output_path = tmp_path / "validation.json"
    environment_path.write_text(json.dumps(environment), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "validate_profile_catalog.py"),
            "--catalog",
            str(CATALOG_PATH),
            "--environment-report",
            str(environment_path),
            "--output",
            str(output_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["validation_passed"] is True
    assert all(report["profile_tls_group_available"].values())
