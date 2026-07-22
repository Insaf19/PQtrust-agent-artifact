"""Frozen typed configuration for Stage 3B cryptographic calibration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pqtrust_agent.evidence.canonical import canonicalize, domain_separated_sha256

LEGACY_CONFIG_HASH_DOMAIN = "PQTrust.CryptoCalibrationConfig.v1"
EXACT_CONFIGURATION_HASH_DOMAIN = "PQTrust.CryptoCalibration.ExactConfig.v1"
SCIENTIFIC_DESIGN_HASH_DOMAIN = "PQTrust.CryptoCalibration.ScientificDesign.v1"


class CertificatePaths(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ca_certificate: str
    server_certificate: str
    server_private_key: str


class MldsaKeyPaths(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mldsa65_private: str
    mldsa65_public: str
    mldsa87_private: str
    mldsa87_public: str


class NativeExecutablePaths(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    openssl: str
    tls_handshake_bench: str
    mldsa_bench: str


class ReplicateDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    replicate_id: int = Field(ge=1)
    tls_seed: int = Field(gt=0)
    mldsa_seed: int = Field(gt=0)


class CryptoCalibrationConfig(BaseModel):
    """Complete Stage 3B campaign design with no measured values."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"]
    campaign_id: str
    tls_groups: tuple[str, ...]
    mldsa_algorithms: tuple[Literal["ML-DSA-65", "ML-DSA-87"], ...]
    mldsa_message_sizes_bytes: tuple[int, ...]
    warmups_per_case: int = Field(ge=0)
    measured_blocks: int = Field(gt=0)
    replicates: tuple[ReplicateDefinition, ...]
    tls_cipher_suite: Literal["TLS_AES_256_GCM_SHA384"]
    expected_tls_version: Literal["TLSv1.3"]
    certificate_paths: CertificatePaths
    mldsa_key_paths: MldsaKeyPaths
    native_executable_paths: NativeExecutablePaths
    per_process_timeout_seconds: int = Field(gt=0)
    inter_replicate_idle_seconds: int = Field(ge=0)
    cpu_core: int | None = Field(default=None, ge=0)
    max_system_load_warning: int = Field(gt=0)

    @field_validator("tls_groups", mode="before")
    @classmethod
    def _tuple_str(cls, value: Any) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("tls_groups must be a sequence")
        return tuple(str(item) for item in value)

    @field_validator("mldsa_algorithms", mode="before")
    @classmethod
    def _tuple_algorithms(cls, value: Any) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("mldsa_algorithms must be a sequence")
        return tuple(str(item) for item in value)

    @field_validator("mldsa_message_sizes_bytes", mode="before")
    @classmethod
    def _tuple_sizes(cls, value: Any) -> tuple[int, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("mldsa_message_sizes_bytes must be a sequence")
        return tuple(int(item) for item in value)

    @field_validator("replicates", mode="before")
    @classmethod
    def _tuple_replicates(cls, value: Any) -> tuple[Any, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("replicates must be a sequence")
        return tuple(value)

    @model_validator(mode="after")
    def _validate_design(self) -> CryptoCalibrationConfig:
        expected_tls = (
            "X25519",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "MLKEM768",
            "SecP384r1MLKEM1024",
        )
        if self.tls_groups != expected_tls:
            raise ValueError("TLS groups must match the Stage 3B design exactly")
        if self.mldsa_algorithms != ("ML-DSA-65", "ML-DSA-87"):
            raise ValueError("ML-DSA algorithms must match the Stage 3B design exactly")
        if self.mldsa_message_sizes_bytes != (512, 2048, 8192):
            raise ValueError("ML-DSA message sizes must match the Stage 3B design exactly")
        if self.warmups_per_case != 30 or self.measured_blocks != 200:
            raise ValueError("Stage 3B repetition counts must not be reduced")
        observed_ids = tuple(rep.replicate_id for rep in self.replicates)
        if observed_ids != (1, 2, 3):
            raise ValueError("replicate definitions must preserve three ordered replicates")
        if len({rep.tls_seed for rep in self.replicates}) != len(self.replicates):
            raise ValueError("TLS scheduling seeds must be distinct")
        if len({rep.mldsa_seed for rep in self.replicates}) != len(self.replicates):
            raise ValueError("ML-DSA scheduling seeds must be distinct")
        return self

    def canonical_bytes(self) -> bytes:
        return canonicalize(self)

    def config_hash(self) -> str:
        return domain_separated_sha256(LEGACY_CONFIG_HASH_DOMAIN, self)

    def exact_configuration_hash(self) -> str:
        return domain_separated_sha256(EXACT_CONFIGURATION_HASH_DOMAIN, self)

    def scientific_design_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload.pop("campaign_id", None)
        payload["replicate_count"] = len(self.replicates)
        payload.pop("replicates", None)
        return payload

    def scientific_design_hash(self) -> str:
        return domain_separated_sha256(
            SCIENTIFIC_DESIGN_HASH_DOMAIN, self.scientific_design_payload()
        )

    def expected_tls_records_per_replicate(self) -> int:
        return self.measured_blocks * len(self.tls_groups)

    def expected_mldsa_records_per_replicate(self) -> int:
        return (
            self.measured_blocks
            * len(self.mldsa_algorithms)
            * len(self.mldsa_message_sizes_bytes)
        )

    def expected_tls_records_total(self) -> int:
        return self.expected_tls_records_per_replicate() * len(self.replicates)

    def expected_mldsa_records_total(self) -> int:
        return self.expected_mldsa_records_per_replicate() * len(self.replicates)


def load_calibration_config(path: Path) -> CryptoCalibrationConfig:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return CryptoCalibrationConfig.model_validate(loaded)
