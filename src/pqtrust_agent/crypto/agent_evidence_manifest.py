"""Typed loading and local resolution for agent evidence keys."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqtrust_agent.models.common import EvidenceAlgorithm, canonical_evidence_algorithm
from pqtrust_agent.models.protocol import SHA256_HEX_RE

EXPECTED_AGENT_IDS: tuple[str, ...] = (
    "cloud-orchestrator",
    "public-tool-agent",
    "enterprise-api-agent",
    "edge-control-agent",
    "quantum-ready-tool-agent",
)
EXPECTED_ALGORITHMS: tuple[EvidenceAlgorithm, ...] = (
    EvidenceAlgorithm.ML_DSA_65,
    EvidenceAlgorithm.ML_DSA_87,
)
EXPECTED_KEY_COUNT = len(EXPECTED_AGENT_IDS) * len(EXPECTED_ALGORITHMS)
LAB_AGENT_KEY_ROOT = Path(".local/pqtrust-crypto/agents")


@dataclass(frozen=True, order=True)
class KeyLocator:
    """Deterministic composite key for agent evidence material."""

    agent_id: str
    canonical_algorithm: EvidenceAlgorithm


@dataclass(frozen=True)
class ManifestFailure:
    """Structured manifest or local-key validation failure."""

    scenario_id: str | None
    phase: str
    agent_id: str | None
    requested_algorithm: str | None
    error_code: str
    message: str
    debug: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "scenario_id": self.scenario_id,
            "phase": self.phase,
            "agent_id": self.agent_id,
            "requested_algorithm": self.requested_algorithm,
            "error_code": self.error_code,
            "message": self.message,
            "debug": self.debug,
        }


class AgentEvidenceManifestError(ValueError):
    """Raised when an agent evidence-key manifest fails closed."""

    def __init__(self, failures: list[ManifestFailure]) -> None:
        self.failures = failures
        super().__init__("; ".join(f"{item.error_code}: {item.message}" for item in failures))


@dataclass(frozen=True)
class AgentEvidenceKeyManifestEntry:
    agent_id: str
    algorithm: EvidenceAlgorithm
    key_id: str
    public_key_sha256: str
    public_key_path: Path
    local_relative_path: str
    validation_status: str

    @property
    def locator(self) -> KeyLocator:
        return KeyLocator(self.agent_id, self.algorithm)


@dataclass(frozen=True)
class AgentEvidenceKeyManifest:
    manifest_path: Path
    repo_root: Path
    entries: tuple[AgentEvidenceKeyManifestEntry, ...]
    index: dict[KeyLocator, AgentEvidenceKeyManifestEntry]

    def get(
        self,
        agent_id: str,
        algorithm: str | EvidenceAlgorithm,
    ) -> AgentEvidenceKeyManifestEntry:
        try:
            canonical = canonical_evidence_algorithm(algorithm)
        except ValueError as exc:
            raise AgentEvidenceManifestError(
                [
                    ManifestFailure(
                        scenario_id=None,
                        phase="key_manifest_lookup",
                        agent_id=agent_id,
                        requested_algorithm=str(algorithm),
                        error_code="KEY_ALGORITHM_UNSUPPORTED",
                        message=str(exc),
                        debug=repr(algorithm),
                    )
                ]
            ) from exc
        locator = KeyLocator(agent_id, canonical)
        try:
            return self.index[locator]
        except KeyError as exc:
            raise AgentEvidenceManifestError(
                [
                    ManifestFailure(
                        scenario_id=None,
                        phase="key_manifest_lookup",
                        agent_id=agent_id,
                        requested_algorithm=canonical.value,
                        error_code="KEY_MANIFEST_ENTRY_MISSING",
                        message=f"missing key manifest entry for {agent_id} {canonical.value}",
                        debug=repr(locator),
                    )
                ]
            ) from exc

    def expected_keys(self) -> dict[KeyLocator, tuple[str, str, Path]]:
        return {
            entry.locator: (entry.key_id, entry.public_key_sha256, entry.public_key_path)
            for entry in self.entries
        }


def expected_key_locators() -> tuple[KeyLocator, ...]:
    return tuple(
        KeyLocator(agent_id, algorithm)
        for agent_id in EXPECTED_AGENT_IDS
        for algorithm in EXPECTED_ALGORITHMS
    )


def canonical_key_id(agent_id: str, algorithm: EvidenceAlgorithm) -> str:
    return f"{agent_id}:{algorithm.value}:lab-v1"


def algorithm_filename_stem(algorithm: EvidenceAlgorithm) -> str:
    return algorithm.value.lower().replace("-", "")


def _failure(
    *,
    phase: str,
    error_code: str,
    message: str,
    agent_id: str | None = None,
    requested_algorithm: str | None = None,
    debug: str | None = None,
) -> ManifestFailure:
    return ManifestFailure(
        scenario_id=None,
        phase=phase,
        agent_id=agent_id,
        requested_algorithm=requested_algorithm,
        error_code=error_code,
        message=message,
        debug=debug,
    )


def _repo_path(repo_root: Path, relative_path: str, failures: list[ManifestFailure]) -> Path:
    raw = Path(relative_path)
    if raw.is_absolute() or ".." in raw.parts:
        failures.append(
            _failure(
                phase="key_manifest_load",
                error_code="KEY_PATH_INVALID",
                message=(
                    "public key path must be repository-relative and non-escaping: "
                    f"{relative_path}"
                ),
            )
        )
        return repo_root / "__invalid__"
    resolved = (repo_root / raw).resolve()
    if not resolved.is_relative_to(repo_root):
        failures.append(
            _failure(
                phase="key_manifest_load",
                error_code="KEY_PATH_INVALID",
                message=f"public key path escapes repository root: {relative_path}",
            )
        )
    return resolved


def _fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_agent_evidence_key_manifest(
    manifest_path: Path,
    *,
    repo_root: Path,
) -> AgentEvidenceKeyManifest:
    """Load and fully validate the public agent evidence-key manifest."""

    repo_root = repo_root.resolve()
    resolved_manifest = (
        (repo_root / manifest_path).resolve()
        if not manifest_path.is_absolute()
        else manifest_path.resolve()
    )
    raw = json.loads(resolved_manifest.read_text(encoding="utf-8"))
    failures: list[ManifestFailure] = []
    raw_keys = raw.get("keys")
    if not isinstance(raw_keys, list):
        raise AgentEvidenceManifestError(
            [
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_MANIFEST_MALFORMED",
                    message="agent evidence manifest must contain a keys list",
                )
            ]
        )

    index: dict[KeyLocator, AgentEvidenceKeyManifestEntry] = {}
    entries: list[AgentEvidenceKeyManifestEntry] = []
    seen_key_ids: set[str] = set()
    for offset, item in enumerate(raw_keys):
        if not isinstance(item, dict):
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_MANIFEST_MALFORMED",
                    message=f"key manifest entry {offset} must be an object",
                )
            )
            continue
        agent_id = str(item.get("agent_id", ""))
        if agent_id not in EXPECTED_AGENT_IDS:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_AGENT_UNKNOWN",
                    message=f"unknown agent evidence key owner: {agent_id}",
                    agent_id=agent_id or None,
                )
            )
        try:
            algorithm = canonical_evidence_algorithm(str(item.get("algorithm", "")))
        except ValueError as exc:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_ALGORITHM_UNSUPPORTED",
                    message=str(exc),
                    agent_id=agent_id or None,
                    requested_algorithm=str(item.get("algorithm", "")) or None,
                    debug=f"entry={offset}",
                )
            )
            continue
        key_id = str(item.get("key_id", ""))
        if not key_id:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_ID_EMPTY",
                    message=f"empty key ID for {agent_id} {algorithm.value}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        elif key_id in seen_key_ids:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_ID_DUPLICATE",
                    message=f"duplicate key ID: {key_id}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        seen_key_ids.add(key_id)
        expected_key_id = canonical_key_id(agent_id, algorithm)
        if key_id and key_id != expected_key_id:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_ID_MISMATCH",
                    message=f"key ID {key_id} does not match {expected_key_id}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        public_key_sha256 = str(item.get("public_key_sha256", ""))
        if __import__("re").fullmatch(SHA256_HEX_RE, public_key_sha256) is None:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="PUBLIC_KEY_FINGERPRINT_MALFORMED",
                    message=f"malformed public key SHA-256 for {agent_id} {algorithm.value}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        local_relative_path = str(item.get("local_relative_path", ""))
        public_path = _repo_path(repo_root, local_relative_path, failures)
        expected_prefix = LAB_AGENT_KEY_ROOT / agent_id
        raw_relative = Path(local_relative_path)
        if raw_relative.parts[: len(expected_prefix.parts)] != expected_prefix.parts:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_PATH_MISMATCH",
                    message=(
                        "public key path does not match agent key layout: "
                        f"{local_relative_path}"
                    ),
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        if raw_relative.name.endswith(".public.pem"):
            path_algorithm = raw_relative.name.removesuffix(".public.pem")
            try:
                path_canonical = canonical_evidence_algorithm(path_algorithm)
                if path_canonical != algorithm:
                    failures.append(
                        _failure(
                            phase="key_manifest_load",
                            error_code="KEY_ALGORITHM_MISMATCH",
                            message="manifest algorithm does not match public key filename",
                            agent_id=agent_id,
                            requested_algorithm=algorithm.value,
                            debug=f"path_algorithm={path_algorithm}",
                        )
                    )
            except ValueError as exc:
                failures.append(
                    _failure(
                        phase="key_manifest_load",
                        error_code="KEY_ALGORITHM_MISMATCH",
                        message=str(exc),
                        agent_id=agent_id,
                        requested_algorithm=algorithm.value,
                    )
                )
        else:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_PATH_MISMATCH",
                    message=f"public key path must end in .public.pem: {local_relative_path}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        if public_path.exists():
            actual_fingerprint = _fingerprint(public_path)
            if (
                __import__("re").fullmatch(SHA256_HEX_RE, public_key_sha256) is not None
                and actual_fingerprint != public_key_sha256
            ):
                failures.append(
                    _failure(
                        phase="key_manifest_load",
                        error_code="PUBLIC_KEY_FINGERPRINT_MISMATCH",
                        message=f"public key fingerprint mismatch for {agent_id} {algorithm.value}",
                        agent_id=agent_id,
                        requested_algorithm=algorithm.value,
                        debug=f"expected={public_key_sha256} actual={actual_fingerprint}",
                    )
                )
        else:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="PUBLIC_KEY_NOT_FOUND",
                    message=f"public key file does not exist: {local_relative_path}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )

        entry = AgentEvidenceKeyManifestEntry(
            agent_id=agent_id,
            algorithm=algorithm,
            key_id=key_id,
            public_key_sha256=public_key_sha256,
            public_key_path=public_path,
            local_relative_path=local_relative_path,
            validation_status=str(item.get("validation_status", "")),
        )
        locator = entry.locator
        if locator in index:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_MANIFEST_DUPLICATE",
                    message=f"duplicate key manifest entry for {agent_id} {algorithm.value}",
                    agent_id=agent_id,
                    requested_algorithm=algorithm.value,
                )
            )
        else:
            index[locator] = entry
            entries.append(entry)

    for locator in expected_key_locators():
        if locator not in index:
            failures.append(
                _failure(
                    phase="key_manifest_load",
                    error_code="KEY_MANIFEST_ENTRY_MISSING",
                    message=(
                        "missing key manifest entry for "
                        f"{locator.agent_id} {locator.canonical_algorithm.value}"
                    ),
                    agent_id=locator.agent_id,
                    requested_algorithm=locator.canonical_algorithm.value,
                )
            )

    if failures:
        raise AgentEvidenceManifestError(failures)
    return AgentEvidenceKeyManifest(
        manifest_path=resolved_manifest,
        repo_root=repo_root,
        entries=tuple(sorted(entries, key=lambda item: item.locator)),
        index=index,
    )


def resolve_local_agent_evidence_key(
    manifest: AgentEvidenceKeyManifest,
    *,
    agent_id: str,
    role: str,
    algorithm: str | EvidenceAlgorithm,
    signer: Any,
) -> Any:
    """Resolve and validate the local private key for laboratory signing."""

    from pqtrust_agent.crypto.contract_signer import AgentEvidenceKey

    entry = manifest.get(agent_id, algorithm)
    private_path = entry.public_key_path.with_name(
        entry.public_key_path.name.removesuffix(".public.pem") + ".private.pem"
    )
    failures: list[ManifestFailure] = []
    if not private_path.exists():
        failures.append(
            _failure(
                phase="local_private_key_resolution",
                error_code="PRIVATE_KEY_NOT_FOUND",
                message=f"private key file does not exist for {agent_id} {entry.algorithm.value}",
                agent_id=agent_id,
                requested_algorithm=entry.algorithm.value,
            )
        )
    else:
        mode = stat.S_IMODE(private_path.stat().st_mode)
        if mode & 0o077:
            failures.append(
                _failure(
                    phase="local_private_key_resolution",
                    error_code="PRIVATE_KEY_PERMISSIONS_INVALID",
                    message=f"private key file must not be group/world-readable: {private_path}",
                    agent_id=agent_id,
                    requested_algorithm=entry.algorithm.value,
                    debug=f"mode={mode:o}",
                )
            )
    actual_public_hash = _fingerprint(entry.public_key_path)
    if actual_public_hash != entry.public_key_sha256:
        failures.append(
            _failure(
                phase="local_private_key_resolution",
                error_code="PUBLIC_KEY_FINGERPRINT_MISMATCH",
                message=f"public key fingerprint mismatch for {agent_id} {entry.algorithm.value}",
                agent_id=agent_id,
                requested_algorithm=entry.algorithm.value,
            )
        )
    expected_key_id = canonical_key_id(agent_id, entry.algorithm)
    if entry.key_id != expected_key_id:
        failures.append(
            _failure(
                phase="local_private_key_resolution",
                error_code="KEY_ID_MISMATCH",
                message=f"manifest key ID {entry.key_id} does not match {expected_key_id}",
                agent_id=agent_id,
                requested_algorithm=entry.algorithm.value,
            )
        )
    if not failures and not signer.verify_private_public_pair(private_path, entry.public_key_path):
        failures.append(
            _failure(
                phase="local_private_key_resolution",
                error_code="PRIVATE_PUBLIC_KEY_MISMATCH",
                message=f"private/public key pair mismatch for {agent_id} {entry.algorithm.value}",
                agent_id=agent_id,
                requested_algorithm=entry.algorithm.value,
            )
        )
    if failures:
        raise AgentEvidenceManifestError(failures)
    return AgentEvidenceKey(
        agent_id=entry.agent_id,
        role=role,
        key_id=entry.key_id,
        algorithm=entry.algorithm,
        private_key_path=private_path,
        public_key_path=entry.public_key_path,
        public_key_sha256=entry.public_key_sha256,
    )
