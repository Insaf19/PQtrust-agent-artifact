"""Canonical TLS group names and OpenSSL boundary normalization."""

from __future__ import annotations

from dataclasses import dataclass

TLS_GROUP_NEGOTIATION_MISMATCH = "TLS_GROUP_NEGOTIATION_MISMATCH"
TLS_GROUP_UNKNOWN = "TLS_GROUP_UNKNOWN"
TLS_GROUP_PARSE_FAILED = "TLS_GROUP_PARSE_FAILED"

CANONICAL_TLS_GROUPS: tuple[str, ...] = (
    "X25519",
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "MLKEM768",
    "SecP384r1MLKEM1024",
)

PROFILE_TLS_GROUPS: dict[str, str] = {
    "P0": "X25519",
    "P1": "X25519MLKEM768",
    "P2": "SecP256r1MLKEM768",
    "P3": "MLKEM768",
    "P4": "SecP384r1MLKEM1024",
}

_OPENSSL_ALIAS_TO_CANONICAL: dict[str, str] = {
    "X25519": "X25519",
    "x25519": "X25519",
    "X25519MLKEM768": "X25519MLKEM768",
    "x25519mlkem768": "X25519MLKEM768",
    "SecP256r1MLKEM768": "SecP256r1MLKEM768",
    "secp256r1mlkem768": "SecP256r1MLKEM768",
    "MLKEM768": "MLKEM768",
    "mlkem768": "MLKEM768",
    "SecP384r1MLKEM1024": "SecP384r1MLKEM1024",
    "secp384r1mlkem1024": "SecP384r1MLKEM1024",
}


@dataclass(frozen=True)
class TlsGroupDiagnostics:
    requested_raw: str
    negotiated_raw: str
    requested_canonical: str
    negotiated_canonical: str
    server_negotiated_raw: str | None = None
    server_negotiated_canonical: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "requested_raw": self.requested_raw,
            "negotiated_raw": self.negotiated_raw,
            "requested_canonical": self.requested_canonical,
            "negotiated_canonical": self.negotiated_canonical,
            "server_negotiated_raw": self.server_negotiated_raw,
            "server_negotiated_canonical": self.server_negotiated_canonical,
        }


class TlsGroupError(ValueError):
    """Fail-closed TLS group error with stable code and exact observed values."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        diagnostics: TlsGroupDiagnostics | None = None,
        raw_value: str | None = None,
    ) -> None:
        self.code = code
        self.diagnostics = diagnostics
        self.raw_value = raw_value
        parts = [code, message]
        if raw_value is not None:
            parts.append(f"raw_value={raw_value!r}")
        if diagnostics is not None:
            parts.append(f"diagnostics={diagnostics.as_dict()!r}")
        super().__init__(": ".join(parts))


def canonical_tls_group(value: str) -> str:
    """Return the registered canonical TLS group name for an OpenSSL boundary value."""

    if not isinstance(value, str) or not value:
        raise TlsGroupError(
            TLS_GROUP_PARSE_FAILED,
            "TLS group must be a nonempty string",
            raw_value=str(value),
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TlsGroupError(
            TLS_GROUP_PARSE_FAILED,
            "TLS group must be valid UTF-8 text",
            raw_value=value,
        ) from exc
    if any(ord(character) < 0x20 for character in value):
        raise TlsGroupError(
            TLS_GROUP_PARSE_FAILED,
            "TLS group contains a control character",
            raw_value=value,
        )
    canonical = _OPENSSL_ALIAS_TO_CANONICAL.get(value)
    if canonical is None:
        raise TlsGroupError(
            TLS_GROUP_UNKNOWN,
            "TLS group is not a registered canonical group or documented OpenSSL alias",
            raw_value=value,
        )
    return canonical


def require_registered_canonical_tls_group(value: str) -> str:
    """Validate that repository-owned configuration uses canonical names only."""

    if value not in CANONICAL_TLS_GROUPS:
        raise TlsGroupError(
            TLS_GROUP_UNKNOWN,
            "repository TLS group must use a registered canonical name",
            raw_value=value,
        )
    return value


def tls_group_diagnostics(
    *,
    requested: str,
    negotiated: str,
    server_negotiated: str | None = None,
) -> TlsGroupDiagnostics:
    server_canonical = (
        canonical_tls_group(server_negotiated) if server_negotiated is not None else None
    )
    return TlsGroupDiagnostics(
        requested_raw=requested,
        negotiated_raw=negotiated,
        requested_canonical=canonical_tls_group(requested),
        negotiated_canonical=canonical_tls_group(negotiated),
        server_negotiated_raw=server_negotiated,
        server_negotiated_canonical=server_canonical,
    )


def require_matching_tls_groups(
    *,
    requested: str,
    negotiated: str,
    server_negotiated: str | None = None,
) -> TlsGroupDiagnostics:
    diagnostics = tls_group_diagnostics(
        requested=requested,
        negotiated=negotiated,
        server_negotiated=server_negotiated,
    )
    if diagnostics.requested_canonical != diagnostics.negotiated_canonical:
        raise TlsGroupError(
            TLS_GROUP_NEGOTIATION_MISMATCH,
            "negotiated TLS group differs from requested group",
            diagnostics=diagnostics,
        )
    if (
        diagnostics.server_negotiated_canonical is not None
        and diagnostics.negotiated_canonical != diagnostics.server_negotiated_canonical
    ):
        raise TlsGroupError(
            TLS_GROUP_NEGOTIATION_MISMATCH,
            "client and server negotiated TLS groups differ",
            diagnostics=diagnostics,
        )
    return diagnostics
