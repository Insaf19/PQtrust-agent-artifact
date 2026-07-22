from __future__ import annotations

from pathlib import Path

import pytest

from pqtrust_agent.crypto.smoke_validation import atomic_write_json
from pqtrust_agent.metrics.calibration_config_resolver import (
    DuplicateKeyError,
    load_calibration_config_strict,
    resolve_raw_run_config,
    resolve_raw_run_config_with_optional_external,
)
from pqtrust_agent.metrics.calibration_models import load_calibration_config

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_CONFIG = REPO_ROOT / "configs/calibration/crypto_calibration.yaml"
CONFIRMATORY_CONFIG = REPO_ROOT / "configs/calibration/crypto_calibration_confirmatory.yaml"


def _fixture_run(tmp_path: Path, config_path: Path) -> Path:
    run_dir = tmp_path / "fixture-raw-run"
    run_dir.mkdir()
    config = load_calibration_config(config_path)
    (run_dir / "config_snapshot.yaml").write_text(
        config_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    atomic_write_json(
        run_dir / "run_manifest.json",
        {
            "schema_version": 1,
            "run_id": "fixture-raw-run",
            "calibration_configuration_hash": config.config_hash(),
            "exact_configuration_hash": config.exact_configuration_hash(),
            "scientific_design_hash": config.scientific_design_hash(),
        },
    )
    return run_dir


def test_resolver_uses_raw_snapshot_without_config(tmp_path: Path) -> None:
    run_dir = _fixture_run(tmp_path, CONFIRMATORY_CONFIG)

    resolved = resolve_raw_run_config_with_optional_external(run_dir, None)

    assert resolved.config.campaign_id == "stage3c_crypto_calibration_confirmatory_v1"
    assert resolved.manifest_configuration_hash_matches is True


def test_explicit_matching_config_is_accepted(tmp_path: Path) -> None:
    run_dir = _fixture_run(tmp_path, BASELINE_CONFIG)

    resolved = resolve_raw_run_config_with_optional_external(run_dir, BASELINE_CONFIG)

    assert resolved.config.campaign_id == "stage3b_crypto_calibration_v1"


def test_explicit_mismatching_config_is_rejected(tmp_path: Path) -> None:
    run_dir = _fixture_run(tmp_path, CONFIRMATORY_CONFIG)

    with pytest.raises(ValueError, match="external configuration does not match"):
        resolve_raw_run_config_with_optional_external(run_dir, BASELINE_CONFIG)


def test_no_silent_fallback_to_baseline_config(tmp_path: Path) -> None:
    run_dir = _fixture_run(tmp_path, CONFIRMATORY_CONFIG)

    resolved = resolve_raw_run_config(run_dir)

    assert resolved.config.exact_configuration_hash() != load_calibration_config(
        BASELINE_CONFIG
    ).exact_configuration_hash()


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: '1.0'\nschema_version: '1.0'\n", encoding="utf-8")

    with pytest.raises(DuplicateKeyError):
        load_calibration_config_strict(path)
