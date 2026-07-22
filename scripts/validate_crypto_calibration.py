#!/usr/bin/env python3
"""Validate Stage 3B raw calibration evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

from pqtrust_agent.crypto.smoke_validation import atomic_write_json
from pqtrust_agent.metrics.calibration_config_resolver import (
    resolve_raw_run_config_with_optional_external,
)
from pqtrust_agent.metrics.validation import validate_raw_run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Optional external config to verify against the raw run's config_snapshot.yaml. "
            "When omitted, the raw-run snapshot is used."
        ),
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--raw-root", type=Path, default=Path("runs/raw/crypto_calibration"))
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts/calibration"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    config_path = (
        None
        if args.config is None
        else args.config
        if args.config.is_absolute()
        else repo_root / args.config
    )
    raw_root = args.raw_root if args.raw_root.is_absolute() else repo_root / args.raw_root
    artifact_root = (
        args.artifact_root if args.artifact_root.is_absolute() else repo_root / args.artifact_root
    )
    run_dir = raw_root / args.run_id
    resolved = resolve_raw_run_config_with_optional_external(run_dir, config_path)
    report = validate_raw_run(run_dir, resolved.config)
    atomic_write_json(artifact_root / args.run_id / "validation_report.json", report)
    return 0 if report["validation_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
