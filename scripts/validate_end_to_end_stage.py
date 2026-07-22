#!/usr/bin/env python3
"""Generate the complete deterministic Stage 7 runtime evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqtrust_agent.runtime.stage7_evidence import generate_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/runtime"))
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument(
        "--scenario", help="accepted for CLI symmetry; Stage 7 bundle is all-scenario"
    )
    parser.add_argument("--runtime-dir", type=Path, help="alias for --output-dir")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output_dir = args.runtime_dir or args.output_dir
    if args.scenario and args.verbose:
        print("Stage 7 bundle generation always validates all scenarios.")
    report = generate_bundle(repo, output_dir, replace_existing=args.replace_existing)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
