"""Contract-bound TLS execution wrapper."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pqtrust_agent.crypto.native_runner import NativeRunner
from pqtrust_agent.models.transport import AuthorizedExecutionContext, TlsExecutionResult
from pqtrust_agent.tls_groups import (
    PROFILE_TLS_GROUPS,
    require_matching_tls_groups,
    require_registered_canonical_tls_group,
)


class TlsExecutor:
    """Run the repository-local native TLS handshake binary."""

    def __init__(
        self,
        *,
        binary: Path = Path("build/native/tls_handshake_bench"),
        certificate: Path = Path("artifacts/smoke/crypto_smoke/material_manifest.json"),
        timeout_seconds: float = 15.0,
    ) -> None:
        self.binary = binary
        self.certificate = certificate
        self.timeout_seconds = timeout_seconds
        self.invocation_count = 0

    def execute(
        self,
        context: AuthorizedExecutionContext,
        *,
        certificate: Path,
        private_key: Path,
        ca_certificate: Path,
    ) -> TlsExecutionResult:
        expected = PROFILE_TLS_GROUPS[context.selected_profile_id]
        requested_group = require_registered_canonical_tls_group(context.tls_group)
        if requested_group != expected:
            raise ValueError("requested TLS group different from selected profile")
        self.invocation_count += 1
        with tempfile.TemporaryDirectory(prefix="pqtrust-stage7-tls-") as temp_dir:
            output = Path(temp_dir) / "tls.jsonl"
            command = [
                str(self.binary),
                "--groups",
                requested_group,
                "--certificate",
                str(certificate),
                "--private-key",
                str(private_key),
                "--ca-certificate",
                str(ca_certificate),
                "--warmups",
                "0",
                "--repetitions",
                "1",
                "--seed",
                "7",
                "--output",
                str(output),
            ]
            result = NativeRunner(timeout_seconds=self.timeout_seconds).run(
                command,
                output,
                "tls13_handshake",
            )
        record = result.records[0]
        require_matching_tls_groups(
            requested=str(record["requested_group"]),
            negotiated=str(record["negotiated_group"]),
            server_negotiated=str(record.get("server_negotiated_group"))
            if record.get("server_negotiated_group") is not None
            else None,
        )
        return TlsExecutionResult(
            requested_tls_group=str(record["requested_group"]),
            negotiated_tls_group=str(record["negotiated_group"]),
            tls_version=str(record["tls_version"]),
            cipher_suite=str(record["cipher_suite"]),
            endpoint_authentication_result="verified"
            if record.get("certificate_verify_result") == 0
            else "failed",
            handshake_success=bool(record["success"]),
            fallback_attempted=False,
            resumption_used=bool(record["session_reused"]),
            native_tls_invoked=True,
        )


class MockTlsExecutor(TlsExecutor):
    """Cheap deterministic TLS executor for unit tests."""

    def __init__(self) -> None:
        super().__init__()

    def execute(
        self,
        context: AuthorizedExecutionContext,
        *,
        certificate: Path,
        private_key: Path,
        ca_certificate: Path,
    ) -> TlsExecutionResult:
        del certificate, private_key, ca_certificate
        self.invocation_count += 1
        requested_group = require_registered_canonical_tls_group(context.tls_group)
        return TlsExecutionResult(
            requested_tls_group=requested_group,
            negotiated_tls_group=requested_group,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            endpoint_authentication_result="verified",
            handshake_success=True,
            fallback_attempted=False,
            resumption_used=False,
            native_tls_invoked=True,
        )
