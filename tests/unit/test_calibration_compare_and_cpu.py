from __future__ import annotations

import json
import shutil
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

from pqtrust_agent.crypto.calibration_runner import select_cpu, selected_cpu_from_run
from pqtrust_agent.metrics.calibration_models import load_calibration_config

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = spec_from_file_location(
    "compare_crypto_calibrations", REPO_ROOT / "scripts/compare_crypto_calibrations.py"
)
assert SPEC is not None and SPEC.loader is not None
COMPARE_MODULE = module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPARE_MODULE
SPEC.loader.exec_module(COMPARE_MODULE)
combined_summary = COMPARE_MODULE.combined_summary
compatibility_report = COMPARE_MODULE.compatibility_report


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )


def _copy_config(path: Path, target: Path) -> None:
    target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def _minimal_run(tmp_path: Path, name: str, config_path: Path) -> Path:
    run_dir = tmp_path / name
    run_dir.mkdir()
    config = load_calibration_config(config_path)
    _copy_config(config_path, run_dir / "config_snapshot.yaml")
    _write_json(
        run_dir / "run_manifest.json",
        {
            "calibration_configuration_hash": config.config_hash(),
            "exact_configuration_hash": config.exact_configuration_hash(),
            "scientific_design_hash": config.scientific_design_hash(),
            "catalog_hash": "catalog",
            "openssl_version": "OpenSSL 3.5.7",
            "selected_cpu": 0,
        },
    )
    for replicate in range(1, 4):
        replicate_dir = run_dir / "replicates" / f"replicate-{replicate:02d}"
        hashes = {"tls_handshake_bench": "tls", "mldsa_bench": "mldsa"}
        _write_json(replicate_dir / "pre_state.json", {"native_executable_hashes": hashes})
        tls_rows = []
        for block, group in enumerate(config.tls_groups):
            tls_rows.append(
                {
                    "block": block,
                    "requested_group": group,
                    "wall_time_ns": 100 + replicate,
                    "process_cpu_time_ns": 90 + replicate,
                    "client_to_server_bytes": 1,
                    "server_to_client_bytes": 2,
                    "total_handshake_bytes": 3,
                }
            )
        _write_jsonl(replicate_dir / "tls_handshakes.jsonl", tls_rows)
        mldsa_rows = []
        for algorithm in config.mldsa_algorithms:
            for size in config.mldsa_message_sizes_bytes:
                mldsa_rows.append(
                    {
                        "block": 0,
                        "algorithm": algorithm,
                        "message_size_bytes": size,
                        "sign_time_ns": 200 + replicate,
                        "verify_time_ns": 150 + replicate,
                        "signature_size_bytes": 42,
                    }
                )
        _write_jsonl(replicate_dir / "mldsa.jsonl", mldsa_rows)
    return run_dir


def test_cross_run_incompatibility_rejection(tmp_path) -> None:
    baseline = _minimal_run(
        tmp_path, "baseline", REPO_ROOT / "configs/calibration/crypto_calibration.yaml"
    )
    confirmatory = _minimal_run(
        tmp_path,
        "confirmatory",
        REPO_ROOT / "configs/calibration/crypto_calibration_confirmatory.yaml",
    )
    manifest = json.loads((confirmatory / "run_manifest.json").read_text(encoding="utf-8"))
    manifest["openssl_version"] = "OpenSSL 3.5.8"
    _write_json(confirmatory / "run_manifest.json", manifest)

    report = compatibility_report(baseline, confirmatory)

    assert report["comparison_compatible"] is False
    assert report["OpenSSL_versions_match"] is False


def test_exact_hash_mismatch_alone_does_not_reject_comparison(tmp_path) -> None:
    baseline = _minimal_run(
        tmp_path, "baseline", REPO_ROOT / "configs/calibration/crypto_calibration.yaml"
    )
    confirmatory = _minimal_run(
        tmp_path,
        "confirmatory",
        REPO_ROOT / "configs/calibration/crypto_calibration_confirmatory.yaml",
    )

    report = compatibility_report(baseline, confirmatory)

    assert report["exact_configuration_hashes_match"] is False
    assert report["scientific_design_hashes_match"] is True
    assert report["comparison_compatible"] is True


def test_six_replicate_aggregation_preserves_identity_only_when_called(tmp_path) -> None:
    baseline = _minimal_run(
        tmp_path, "baseline", REPO_ROOT / "configs/calibration/crypto_calibration.yaml"
    )
    confirmatory = _minimal_run(
        tmp_path,
        "confirmatory",
        REPO_ROOT / "configs/calibration/crypto_calibration_confirmatory.yaml",
    )

    summary = combined_summary(baseline, confirmatory)

    reps = summary["tls"]["X25519"]["wall_time_ns"]["replicate_identity_preserved"]
    assert reps == [
        "baseline-replicate-01",
        "baseline-replicate-02",
        "baseline-replicate-03",
        "confirmatory-replicate-01",
        "confirmatory-replicate-02",
        "confirmatory-replicate-03",
    ]


def test_cpu_reuse_reads_baseline_manifest_and_validates_current_cpu(tmp_path) -> None:
    raw_root = tmp_path / "raw"
    _write_json(raw_root / "baseline" / "run_manifest.json", {"selected_cpu": 0})

    selected = selected_cpu_from_run(raw_root, "baseline")

    assert select_cpu(str(selected), None) == selected


def test_cpu_reuse_rejects_missing_cpu() -> None:
    if shutil.which("taskset") is None:
        pytest.skip("CPU affinity availability is platform dependent")

    with pytest.raises(ValueError):
        select_cpu("999999", None)
