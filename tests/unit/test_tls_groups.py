from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from pqtrust_agent.crypto.native_runner import NativeRunner
from pqtrust_agent.models.transport import TlsExecutionResult
from pqtrust_agent.tls_groups import (
    CANONICAL_TLS_GROUPS,
    TLS_GROUP_NEGOTIATION_MISMATCH,
    TLS_GROUP_UNKNOWN,
    TlsGroupError,
    canonical_tls_group,
    require_matching_tls_groups,
    require_registered_canonical_tls_group,
)

REPO = Path(__file__).resolve().parents[2]



@pytest.mark.parametrize("group", CANONICAL_TLS_GROUPS)
def test_all_canonical_tls_group_names(group: str) -> None:
    assert require_registered_canonical_tls_group(group) == group
    assert canonical_tls_group(group) == group


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("x25519", "X25519"),
        ("x25519mlkem768", "X25519MLKEM768"),
        ("secp256r1mlkem768", "SecP256r1MLKEM768"),
        ("mlkem768", "MLKEM768"),
        ("secp384r1mlkem1024", "SecP384r1MLKEM1024"),
    ],
)
def test_documented_openssl_alias_normalization(alias: str, canonical: str) -> None:
    assert canonical_tls_group(alias) == canonical


def test_unknown_group_rejected() -> None:
    with pytest.raises(TlsGroupError) as exc_info:
        canonical_tls_group("X25519Kyber768Draft00")
    assert exc_info.value.code == TLS_GROUP_UNKNOWN


def test_actual_negotiated_group_extraction_match() -> None:
    diagnostics = require_matching_tls_groups(
        requested="X25519MLKEM768",
        negotiated="x25519mlkem768",
        server_negotiated="X25519MLKEM768",
    )
    assert diagnostics.negotiated_raw == "x25519mlkem768"
    assert diagnostics.negotiated_canonical == "X25519MLKEM768"


def test_genuine_mismatch_remains_rejected() -> None:
    with pytest.raises(TlsGroupError) as exc_info:
        require_matching_tls_groups(requested="X25519", negotiated="MLKEM768")
    assert exc_info.value.code == TLS_GROUP_NEGOTIATION_MISMATCH
    assert exc_info.value.diagnostics is not None
    assert exc_info.value.diagnostics.requested_raw == "X25519"
    assert exc_info.value.diagnostics.negotiated_raw == "MLKEM768"


def test_tls_execution_result_does_not_assign_negotiated_from_requested() -> None:
    with pytest.raises(ValidationError) as exc_info:
        TlsExecutionResult(
            requested_tls_group="X25519",
            negotiated_tls_group="MLKEM768",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            endpoint_authentication_result="verified",
            handshake_success=True,
            fallback_attempted=False,
            resumption_used=False,
            native_tls_invoked=True,
        )
    text = str(exc_info.value)
    assert "TLS_GROUP_NEGOTIATION_MISMATCH" in text
    assert "requested_raw': 'X25519'" in text
    assert "negotiated_raw': 'MLKEM768'" in text


@pytest.mark.parametrize(
    "group",
    ["X25519", "X25519MLKEM768", "MLKEM768", "SecP384r1MLKEM1024"],
)
def test_real_repository_local_openssl_negotiated_group_extraction(group: str) -> None:
    binary = REPO / ".build/native/tls_handshake_bench"
    material_path = REPO / "artifacts/smoke/crypto_smoke/material_manifest.json"
    if not binary.exists() or not material_path.exists():
        pytest.skip("repository-local native TLS fixture is not built")
    environment_path = REPO / "artifacts/environment/environment_report.json"
    if environment_path.exists():
        environment = json.loads(environment_path.read_text(encoding="utf-8"))
        target_groups = environment.get("openssl", {}).get("target_groups", {})
        if target_groups.get(group) is False:
            pytest.skip(f"{group} is not supported by the repository-local OpenSSL fixture")
    files = json.loads(material_path.read_text(encoding="utf-8"))["files"]
    material = {key: REPO / value["path"] for key, value in files.items()}
    with tempfile.TemporaryDirectory(prefix="pqtrust-test-tls-") as temp:
        output = Path(temp) / "tls.jsonl"
        result = NativeRunner(timeout_seconds=60).run(
            [
                str(binary),
                "--groups",
                group,
                "--certificate",
                str(material["server_certificate"]),
                "--private-key",
                str(material["server_private_key"]),
                "--ca-certificate",
                str(material["ca_certificate"]),
                "--warmups",
                "0",
                "--repetitions",
                "1",
                "--seed",
                "11",
                "--output",
                str(output),
            ],
            output,
            "tls13_handshake",
        )
    record = result.records[0]
    diagnostics = require_matching_tls_groups(
        requested=str(record["requested_group"]),
        negotiated=str(record["negotiated_group"]),
        server_negotiated=str(record["server_negotiated_group"]),
    )
    assert diagnostics.requested_canonical == group
    assert diagnostics.negotiated_raw == record["negotiated_group"]
