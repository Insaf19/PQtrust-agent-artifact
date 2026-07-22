from __future__ import annotations

from pathlib import Path

import pytest

from pqtrust_agent.metrics.calibration_models import (
    CryptoCalibrationConfig,
    load_calibration_config,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_stage3b_config_loads_and_hashes_deterministically() -> None:
    config = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")

    assert config.schema_version == "1.0"
    assert config.expected_tls_records_total() == 3000
    assert config.expected_mldsa_records_total() == 3600
    assert config.canonical_bytes() == config.canonical_bytes()
    assert config.config_hash() == config.config_hash()
    assert config.exact_configuration_hash() != config.config_hash()
    assert config.scientific_design_hash() == config.scientific_design_hash()


def test_config_rejects_reduced_repetition_counts() -> None:
    data = load_calibration_config(
        REPO_ROOT / "configs/calibration/crypto_calibration.yaml"
    ).model_dump(mode="json")
    data["measured_blocks"] = 10

    with pytest.raises(ValueError, match="repetition counts"):
        CryptoCalibrationConfig.model_validate(data)


def test_scientific_design_hash_excludes_seeds_but_exact_hash_includes_them() -> None:
    baseline = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")
    confirmatory = load_calibration_config(
        REPO_ROOT / "configs/calibration/crypto_calibration_confirmatory.yaml"
    )

    assert baseline.scientific_design_hash() == confirmatory.scientific_design_hash()
    assert baseline.exact_configuration_hash() != confirmatory.exact_configuration_hash()


def test_scientific_design_hash_changes_for_design_fields() -> None:
    baseline = load_calibration_config(REPO_ROOT / "configs/calibration/crypto_calibration.yaml")

    different_groups = baseline.model_copy(update={"tls_groups": ("X25519",)})
    different_sizes = baseline.model_copy(update={"mldsa_message_sizes_bytes": (512,)})
    different_blocks = baseline.model_copy(update={"measured_blocks": 201})

    assert different_groups.scientific_design_hash() != baseline.scientific_design_hash()
    assert different_sizes.scientific_design_hash() != baseline.scientific_design_hash()
    assert different_blocks.scientific_design_hash() != baseline.scientific_design_hash()
