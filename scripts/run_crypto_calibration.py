#!/usr/bin/env python3
"""Run the Stage 3B raw cryptographic calibration campaign."""

from __future__ import annotations

import argparse
from pathlib import Path

from pqtrust_agent.crypto.calibration_runner import (
    run_calibration_campaign,
    selected_cpu_from_run,
)
from pqtrust_agent.metrics.calibration_models import load_calibration_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/calibration/crypto_calibration.yaml"),
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", type=Path, default=Path("runs/raw/crypto_calibration"))
    parser.add_argument("--cpu-core", default="auto")
    parser.add_argument("--reuse-cpu-from-run")
    parser.add_argument("--allow-dirty", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    config_path = args.config if args.config.is_absolute() else repo_root / args.config
    output_root = (
        args.output_root if args.output_root.is_absolute() else repo_root / args.output_root
    )
    config = load_calibration_config(config_path)
    cpu_core = str(args.cpu_core)
    if args.reuse_cpu_from_run:
        if args.cpu_core != "auto":
            raise ValueError("--reuse-cpu-from-run cannot be combined with --cpu-core")
        cpu_core = str(selected_cpu_from_run(output_root, str(args.reuse_cpu_from_run)))
    run_dir = run_calibration_campaign(
        repo_root=repo_root,
        config_path=config_path,
        config=config,
        run_id=args.run_id,
        output_root=output_root,
        cpu_core_argument=cpu_core,
        allow_dirty=bool(args.allow_dirty),
    )
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
