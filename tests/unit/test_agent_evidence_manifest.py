"""Agent evidence-key manifest and local resolver tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from pqtrust_agent.crypto.agent_evidence_manifest import (
    EXPECTED_AGENT_IDS,
    EXPECTED_ALGORITHMS,
    EXPECTED_KEY_COUNT,
    AgentEvidenceManifestError,
    KeyLocator,
    canonical_key_id,
    expected_key_locators,
    load_agent_evidence_key_manifest,
    resolve_local_agent_evidence_key,
)
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.common import EvidenceAlgorithm, canonical_evidence_algorithm
from pqtrust_agent.protocol.signature import algorithm_for_contract_evidence


class FakeSigner:
    def __init__(self, valid_pair: bool = True) -> None:
        self.valid_pair = valid_pair

    def verify_private_public_pair(self, private_key_path: Path, public_key_path: Path) -> bool:
        return private_key_path.exists() and public_key_path.exists() and self.valid_pair


def _write_manifest(repo: Path, entries: list[dict[str, Any]]) -> Path:
    path = repo / "artifacts/protocol/agent_evidence_key_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"manifest_version": "1.0", "laboratory_only": True, "keys": entries},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _entry(repo: Path, agent_id: str, algorithm: EvidenceAlgorithm) -> dict[str, str]:
    stem = algorithm.value.lower().replace("-", "")
    public = repo / ".local/pqtrust-crypto/agents" / agent_id / f"{stem}.public.pem"
    private = public.with_name(f"{stem}.private.pem")
    public.parent.mkdir(parents=True, exist_ok=True)
    public.write_bytes(f"{agent_id}:{algorithm.value}:public".encode())
    private.write_bytes(f"{agent_id}:{algorithm.value}:private".encode())
    private.chmod(0o600)
    return {
        "agent_id": agent_id,
        "algorithm": algorithm.value,
        "key_id": canonical_key_id(agent_id, algorithm),
        "public_key_sha256": hashlib.sha256(public.read_bytes()).hexdigest(),
        "local_relative_path": public.relative_to(repo).as_posix(),
        "validation_status": "validated",
    }


def _entries(repo: Path) -> list[dict[str, Any]]:
    return [
        _entry(repo, agent_id, algorithm)
        for agent_id in EXPECTED_AGENT_IDS
        for algorithm in EXPECTED_ALGORITHMS
    ]


def _load(repo: Path) -> Any:
    return load_agent_evidence_key_manifest(
        repo / "artifacts/protocol/agent_evidence_key_manifest.json",
        repo_root=repo,
    )


def _error_codes(exc: pytest.ExceptionInfo[AgentEvidenceManifestError]) -> set[str]:
    return {failure.error_code for failure in exc.value.failures}


def test_complete_manifest_builds_all_ten_expected_composite_keys(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    assert len(manifest.entries) == EXPECTED_KEY_COUNT
    assert set(manifest.index) == set(expected_key_locators())


def test_canonical_algorithm_lookup_for_both_parameter_sets(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    assert manifest.get("cloud-orchestrator", "ML-DSA-65").algorithm == EvidenceAlgorithm.ML_DSA_65
    assert manifest.get("cloud-orchestrator", "ML-DSA-87").algorithm == EvidenceAlgorithm.ML_DSA_87


def test_lowercase_and_internal_algorithm_normalization_at_parser_boundary(tmp_path: Path) -> None:
    entries = _entries(tmp_path)
    entries[0]["algorithm"] = "mldsa65"
    entries[0]["key_id"] = canonical_key_id("cloud-orchestrator", EvidenceAlgorithm.ML_DSA_65)
    _write_manifest(tmp_path, entries)
    manifest = _load(tmp_path)
    assert manifest.get("cloud-orchestrator", "MLDSA65").algorithm == EvidenceAlgorithm.ML_DSA_65
    assert canonical_evidence_algorithm("MLZDSAZ87") == EvidenceAlgorithm.ML_DSA_87


def test_unknown_algorithm_rejected(tmp_path: Path) -> None:
    entries = _entries(tmp_path)
    entries[0]["algorithm"] = "SPHINCS-PLUS"
    _write_manifest(tmp_path, entries)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        _load(tmp_path)
    assert "KEY_ALGORITHM_UNSUPPORTED" in _error_codes(exc)


def test_missing_cloud_orchestrator_key_rejected(tmp_path: Path) -> None:
    entries = [
        entry
        for entry in _entries(tmp_path)
        if not (
            entry["agent_id"] == "cloud-orchestrator"
            and entry["algorithm"] == EvidenceAlgorithm.ML_DSA_65.value
        )
    ]
    _write_manifest(tmp_path, entries)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        _load(tmp_path)
    assert "KEY_MANIFEST_ENTRY_MISSING" in _error_codes(exc)


def test_duplicate_cloud_orchestrator_key_rejected(tmp_path: Path) -> None:
    entries = _entries(tmp_path)
    entries.append(dict(entries[0]))
    _write_manifest(tmp_path, entries)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        _load(tmp_path)
    assert "KEY_MANIFEST_DUPLICATE" in _error_codes(exc)


def test_responder_key_lookup_uses_same_index(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    key = resolve_local_agent_evidence_key(
        manifest,
        agent_id="public-tool-agent",
        role="responder",
        algorithm=EvidenceAlgorithm.ML_DSA_65,
        signer=FakeSigner(),
    )
    assert key.role == "responder"
    assert key.algorithm == EvidenceAlgorithm.ML_DSA_65


def test_relative_path_resolution_independent_of_current_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    manifest = _load(tmp_path)
    assert manifest.get("edge-control-agent", "ML-DSA-87").public_key_path.exists()


def test_path_traversal_rejected(tmp_path: Path) -> None:
    entries = _entries(tmp_path)
    entries[0]["local_relative_path"] = "../outside.public.pem"
    _write_manifest(tmp_path, entries)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        _load(tmp_path)
    assert "KEY_PATH_INVALID" in _error_codes(exc)


def test_malformed_fingerprint_rejected(tmp_path: Path) -> None:
    entries = _entries(tmp_path)
    entries[0]["public_key_sha256"] = "not-a-sha"
    _write_manifest(tmp_path, entries)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        _load(tmp_path)
    assert "PUBLIC_KEY_FINGERPRINT_MALFORMED" in _error_codes(exc)


def test_public_key_fingerprint_mismatch_rejected(tmp_path: Path) -> None:
    entries = _entries(tmp_path)
    entries[0]["public_key_sha256"] = "0" * 64
    _write_manifest(tmp_path, entries)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        _load(tmp_path)
    assert "PUBLIC_KEY_FINGERPRINT_MISMATCH" in _error_codes(exc)


def test_missing_private_key_rejected(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    entry = manifest.get("cloud-orchestrator", "ML-DSA-65")
    entry.public_key_path.with_name("mldsa65.private.pem").unlink()
    with pytest.raises(AgentEvidenceManifestError) as exc:
        resolve_local_agent_evidence_key(
            manifest,
            agent_id="cloud-orchestrator",
            role="initiator",
            algorithm="ML-DSA-65",
            signer=FakeSigner(),
        )
    assert "PRIVATE_KEY_NOT_FOUND" in _error_codes(exc)


def test_private_key_permission_rejection(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    private = manifest.get("cloud-orchestrator", "ML-DSA-65").public_key_path.with_name(
        "mldsa65.private.pem"
    )
    private.chmod(0o644)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        resolve_local_agent_evidence_key(
            manifest,
            agent_id="cloud-orchestrator",
            role="initiator",
            algorithm="ML-DSA-65",
            signer=FakeSigner(),
        )
    assert "PRIVATE_KEY_PERMISSIONS_INVALID" in _error_codes(exc)


def test_profile_catalog_contract_evidence_algorithm_binding() -> None:
    catalog = load_profile_catalog(Path("configs/profiles/trust_profiles.yaml"))
    expected = {
        "P0": EvidenceAlgorithm.ML_DSA_65,
        "P1": EvidenceAlgorithm.ML_DSA_65,
        "P2": EvidenceAlgorithm.ML_DSA_65,
        "P3": EvidenceAlgorithm.ML_DSA_65,
        "P4": EvidenceAlgorithm.ML_DSA_87,
    }
    assert {
        profile_id: algorithm_for_contract_evidence(
            catalog.get_profile(profile_id).contract_evidence_mode
        )
        for profile_id in expected
    } == expected


def test_two_agents_resolve_keys_for_identical_canonical_bytes(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    payload = b'{"canonical":"same"}'
    first = resolve_local_agent_evidence_key(
        manifest,
        agent_id="cloud-orchestrator",
        role="initiator",
        algorithm="ML-DSA-65",
        signer=FakeSigner(),
    )
    second = resolve_local_agent_evidence_key(
        manifest,
        agent_id="public-tool-agent",
        role="responder",
        algorithm="ML-DSA-65",
        signer=FakeSigner(),
    )
    assert first.private_key_path != second.private_key_path
    assert hashlib.sha256(payload).hexdigest() == hashlib.sha256(payload).hexdigest()


def test_structured_error_reporting_instead_of_raw_keyerror(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    with pytest.raises(AgentEvidenceManifestError) as exc:
        manifest.get("cloud-orchestrator", "ML-DSA-44")
    assert "KEY_MANIFEST_ENTRY_MISSING" not in _error_codes(exc)
    assert "unsupported evidence algorithm" in exc.value.failures[0].message


def test_manifest_index_key_is_typed_locator(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _entries(tmp_path))
    manifest = _load(tmp_path)
    assert KeyLocator("cloud-orchestrator", EvidenceAlgorithm.ML_DSA_65) in manifest.index
    assert ("cloud-orchestrator", "ML-DSA-65") not in manifest.index
