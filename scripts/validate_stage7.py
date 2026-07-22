#!/usr/bin/env python3
"""Read-only independent validator for the Stage 7 runtime artifact bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqtrust_agent.runtime.stage7_evidence import validate_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, default=Path("artifacts/runtime"))
    parser.add_argument("--output-dir", type=Path, help="alias for --runtime-dir")
    parser.add_argument("--replace-existing", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--scenario", help="accepted for CLI symmetry; bundle validation is all-scenario"
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    runtime_dir = args.output_dir or args.runtime_dir
    result = validate_bundle(runtime_dir, write_report=False)
    if args.verbose or not result["validation_passed"]:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps({"artifact": result["artifact"], "validation_passed": True}))
    return 0 if result["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
