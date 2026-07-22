#!/usr/bin/env python3
"""Validate the trust-profile catalog against a captured OpenSSL environment report."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pqtrust_agent.models.catalog import ProfileCatalog, load_profile_catalog

EXPECTED_PROFILE_IDS = ("P0", "P1", "P2", "P3", "P4")
OPENSSL_MINIMUM = (3, 5, 0)


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _version_at_least(version: object) -> bool:
    if not isinstance(version, list) or len(version) < 2:
        return False
    parts: list[int] = []
    for item in version[:3]:
        if not isinstance(item, int):
            return False
        parts.append(item)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts) >= OPENSSL_MINIMUM


def _load_environment_report(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("environment report must be a JSON object")
    return loaded


def _validate(catalog: ProfileCatalog | None, environment: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    openssl = environment.get("openssl")
    if not isinstance(openssl, dict):
        openssl = {}
        errors.append("environment report is missing openssl object")

    profile_ids = catalog.profile_ids() if catalog is not None else ()
    tls_groups = (
        tuple(profile.tls_group for profile in catalog.profiles) if catalog is not None else ()
    )
    availability: dict[str, bool] = {}

    if profile_ids != EXPECTED_PROFILE_IDS:
        errors.append(f"profile IDs must be exactly {EXPECTED_PROFILE_IDS!r}")

    target_groups = openssl.get("target_groups")
    if not isinstance(target_groups, dict):
        target_groups = {}
        errors.append("environment report is missing openssl.target_groups")

    for profile in catalog.profiles if catalog is not None else ():
        available = target_groups.get(profile.tls_group) is True
        availability[profile.profile_id] = available
        if not available:
            errors.append(f"{profile.profile_id} TLS group {profile.tls_group} is not available")
        if profile.resource_envelope.has_empirical_values():
            errors.append(f"{profile.profile_id} contains empirical ResourceEnvelope values")

    if not _version_at_least(openssl.get("version_tuple")):
        errors.append("OpenSSL version must be at least 3.5")
    if openssl.get("pq_tls_ready") is not True:
        errors.append("PQ TLS ready must be true")

    return {
        "profile_ids": list(profile_ids),
        "tls_groups": list(tls_groups),
        "openssl_executable": openssl.get("selected_executable") or openssl.get("executable"),
        "openssl_version": openssl.get("version"),
        "profile_tls_group_available": availability,
        "validation_errors": errors,
        "validation_passed": not errors,
    }


def validate_profile_catalog(
    catalog_path: Path,
    environment_report_path: Path,
) -> dict[str, object]:
    """Return a machine-readable validation report."""

    errors: list[str] = []
    catalog: ProfileCatalog | None = None
    environment: dict[str, Any] = {}
    catalog_hash: str | None = None
    catalog_version: str | None = None

    try:
        catalog = load_profile_catalog(catalog_path)
        catalog_hash = catalog.catalog_hash()
        catalog_version = catalog.catalog_version
    except Exception as exc:
        errors.append(f"catalog load failed: {exc}")

    try:
        environment = _load_environment_report(environment_report_path)
    except Exception as exc:
        errors.append(f"environment report load failed: {exc}")

    details = _validate(catalog, environment) if catalog is not None else {
        "profile_ids": [],
        "tls_groups": [],
        "openssl_executable": None,
        "openssl_version": None,
        "profile_tls_group_available": {},
        "validation_errors": [],
        "validation_passed": False,
    }
    detail_errors = cast(list[str], details["validation_errors"])
    profile_ids = cast(list[str], details["profile_ids"])
    all_errors = [*errors, *detail_errors]
    return {
        "timestamp_utc": _timestamp(),
        "catalog_path": str(catalog_path),
        "catalog_version": catalog_version,
        "catalog_hash": catalog_hash,
        "profile_count": len(profile_ids),
        "profile_ids": profile_ids,
        "tls_groups": details["tls_groups"],
        "openssl_executable": details["openssl_executable"],
        "openssl_version": details["openssl_version"],
        "profile_tls_group_available": details["profile_tls_group_available"],
        "validation_passed": not all_errors,
        "validation_errors": all_errors,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("configs/profiles/trust_profiles.yaml"),
    )
    parser.add_argument(
        "--environment-report",
        type=Path,
        default=Path("artifacts/environment/environment_report.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/environment/profile_catalog_validation.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = validate_profile_catalog(args.catalog, args.environment_report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["validation_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
