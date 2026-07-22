"""OpenSSL-backed ML-DSA contract signing helpers."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pqtrust_agent.models.common import EvidenceAlgorithm
from pqtrust_agent.models.contract import AgentContractSignature, UnsignedTrustContract


class ContractSigningError(RuntimeError):
    """Raised when repository-local OpenSSL signing fails."""


@dataclass(frozen=True)
class AgentEvidenceKey:
    agent_id: str
    role: str
    key_id: str
    algorithm: EvidenceAlgorithm
    private_key_path: Path
    public_key_path: Path
    public_key_sha256: str


class OpenSSLContractSigner:
    """Sign and verify contract bytes using repository-local OpenSSL only."""

    def __init__(
        self,
        openssl_path: Path = Path(".local/openssl-3.5.7/bin/openssl"),
        timeout: float = 10.0,
    ) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        self.repo_root = repo_root
        self.openssl_path = (
            (repo_root / openssl_path).resolve() if not openssl_path.is_absolute() else openssl_path
        )
        self.timeout = timeout
        expected = (repo_root / ".local/openssl-3.5.7/bin/openssl").resolve()
        if self.openssl_path != expected:
            raise ContractSigningError(
                f"contract signing requires repository-local OpenSSL: {expected}"
            )
        version = self.openssl_version()
        if "OpenSSL 3.5.7" not in version:
            raise ContractSigningError(
                f"unexpected OpenSSL version for contract signing: {version}"
            )

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        if not self.openssl_path.is_file():
            raise ContractSigningError(f"repository-local OpenSSL is missing: {self.openssl_path}")
        try:
            return subprocess.run(
                [str(self.openssl_path), *args],
                check=False,
                capture_output=True,
                timeout=self.timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContractSigningError("OpenSSL contract operation timed out") from exc

    def openssl_version(self) -> str:
        completed = self._run(["version"])
        if completed.returncode != 0:
            raise ContractSigningError(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout.decode("utf-8", errors="replace").strip()

    def sign_bytes(self, payload: bytes, private_key_path: Path) -> bytes:
        tmpdir = Path(os.environ.get("TMPDIR", "/tmp"))
        with tempfile.NamedTemporaryFile(
            prefix="pqtrust-sign-",
            suffix=".bin",
            dir=tmpdir,
            delete=False,
        ) as in_file:
            in_path = Path(in_file.name)
        with tempfile.NamedTemporaryFile(
            prefix="pqtrust-sign-",
            suffix=".sig",
            dir=tmpdir,
            delete=False,
        ) as out_file:
            out_path = Path(out_file.name)
        try:
            in_path.write_bytes(payload)
            completed = self._run(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    str(private_key_path),
                    "-in",
                    str(in_path),
                    "-out",
                    str(out_path),
                ]
            )
            if completed.returncode != 0:
                raise ContractSigningError(completed.stderr.decode("utf-8", errors="replace"))
            signature = out_path.read_bytes()
            if not signature:
                raise ContractSigningError("OpenSSL produced an empty signature")
            return signature
        finally:
            in_path.unlink(missing_ok=True)
            out_path.unlink(missing_ok=True)

    def verify_bytes(self, payload: bytes, signature: bytes, public_key_path: Path) -> bool:
        tmpdir = Path(os.environ.get("TMPDIR", "/tmp"))
        with tempfile.NamedTemporaryFile(
            prefix="pqtrust-verify-",
            suffix=".bin",
            dir=tmpdir,
            delete=False,
        ) as in_file:
            in_path = Path(in_file.name)
        with tempfile.NamedTemporaryFile(
            prefix="pqtrust-verify-",
            suffix=".sig",
            dir=tmpdir,
            delete=False,
        ) as sig_file:
            sig_path = Path(sig_file.name)
        try:
            in_path.write_bytes(payload)
            sig_path.write_bytes(signature)
            completed = self._run(
                [
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(public_key_path),
                    "-in",
                    str(in_path),
                    "-sigfile",
                    str(sig_path),
                ]
            )
            return completed.returncode == 0
        finally:
            in_path.unlink(missing_ok=True)
            sig_path.unlink(missing_ok=True)

    @staticmethod
    def public_key_sha256(public_key_path: Path) -> str:
        return hashlib.sha256(public_key_path.read_bytes()).hexdigest()

    def verify_private_public_pair(self, private_key_path: Path, public_key_path: Path) -> bool:
        payload = b"PQTrust Stage 5 laboratory evidence key validation\n"
        signature = self.sign_bytes(payload, private_key_path)
        return self.verify_bytes(payload, signature, public_key_path)

    def sign_contract(
        self,
        unsigned_contract: UnsignedTrustContract,
        key: AgentEvidenceKey,
    ) -> AgentContractSignature:
        payload = unsigned_contract.canonical_bytes()
        signature = self.sign_bytes(payload, key.private_key_path)
        public_hash = self.public_key_sha256(key.public_key_path)
        if public_hash != key.public_key_sha256:
            raise ContractSigningError("public key fingerprint mismatch")
        if not self.verify_bytes(payload, signature, key.public_key_path):
            raise ContractSigningError("OpenSSL failed to verify generated contract signature")
        return AgentContractSignature(
            agent_id=key.agent_id,
            role=key.role,  # type: ignore[arg-type]
            key_id=key.key_id,
            algorithm=key.algorithm,
            public_key_sha256=public_hash,
            signature_base64=base64.b64encode(signature).decode("ascii"),
        )
