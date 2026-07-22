#!/usr/bin/env python3
"""Validate the complete Stage 5 laboratory agent evidence-key inventory."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.agent_evidence_manifest import (
    EXPECTED_AGENT_IDS,
    EXPECTED_ALGORITHMS,
    EXPECTED_KEY_COUNT,
    AgentEvidenceManifestError,
    ManifestFailure,
    expected_key_locators,
    load_agent_evidence_key_manifest,
    resolve_local_agent_evidence_key,
)
from pqtrust_agent.crypto.contract_signer import OpenSSLContractSigner
from pqtrust_agent.evidence.decimal_json import dumps_decimal_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-manifest",
        type=Path,
        default=Path("artifacts/protocol/agent_evidence_key_manifest.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/protocol/agent_evidence_key_validation.json"),
    )
    return parser.parse_args()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(dumps_decimal_json(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _raw_observed_count(path: Path) -> int:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    keys = raw.get("keys")
    return len(keys) if isinstance(keys, list) else 0


def _failure_payload(failure: ManifestFailure) -> dict[str, str | None]:
    return failure.to_dict()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    manifest_path = (
        (repo_root / args.key_manifest).resolve()
        if not args.key_manifest.is_absolute()
        else args.key_manifest
    )
    output_path = (
        (repo_root / args.output).resolve() if not args.output.is_absolute() else args.output
    )
    errors: list[dict[str, str | None]] = []
    openssl_version: str | None = None
    local_pairs_validated = 0
    try:
        signer = OpenSSLContractSigner()
        openssl_version = signer.openssl_version()
    except Exception as exc:
        signer = None
        errors.append(
            {
                "scenario_id": None,
                "phase": "openssl_backend",
                "agent_id": None,
                "requested_algorithm": None,
                "error_code": "OPENSSL_BACKEND_INVALID",
                "message": str(exc),
                "debug": repr(exc),
            }
        )
    try:
        manifest = load_agent_evidence_key_manifest(manifest_path, repo_root=repo_root)
    except AgentEvidenceManifestError as exc:
        manifest = None
        errors.extend(_failure_payload(failure) for failure in exc.failures)
    if manifest is not None and signer is not None:
        for locator in expected_key_locators():
            try:
                resolve_local_agent_evidence_key(
                    manifest,
                    agent_id=locator.agent_id,
                    role="initiator",
                    algorithm=locator.canonical_algorithm,
                    signer=signer,
                )
                local_pairs_validated += 1
            except AgentEvidenceManifestError as exc:
                errors.extend(_failure_payload(failure) for failure in exc.failures)

    payload: dict[str, Any] = {
        "artifact": "agent_evidence_key_validation",
        "expected_entry_count": EXPECTED_KEY_COUNT,
        "observed_entry_count": _raw_observed_count(manifest_path),
        "expected_agents": list(EXPECTED_AGENT_IDS),
        "expected_algorithms": [algorithm.value for algorithm in EXPECTED_ALGORITHMS],
        "expected_inventory": [
            {
                "agent_id": locator.agent_id,
                "algorithm": locator.canonical_algorithm.value,
            }
            for locator in expected_key_locators()
        ],
        "unique_key_ids": manifest is not None
        and len({entry.key_id for entry in manifest.entries}) == len(manifest.entries),
        "public_fingerprints_validated": manifest is not None,
        "local_private_public_pairs_validated": local_pairs_validated,
        "openssl_version": openssl_version,
        "validation_errors": errors,
        "validation_passed": not errors and local_pairs_validated == EXPECTED_KEY_COUNT,
    }
    _write_json(output_path, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
