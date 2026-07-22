#!/usr/bin/env python3
"""Generate deterministic Stage 7 execution-gate evidence without native TLS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqtrust_agent.runtime.stage7_evidence import generate_execution_gate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/runtime"))
    parser.add_argument("--runtime-dir", type=Path, help="alias for --output-dir")
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument("--scenario", help="accepted for CLI symmetry; gate cases are fixed")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    output_dir = args.runtime_dir or args.output_dir
    target = output_dir / "execution_gate_validation.json"
    if target.exists() and not args.replace_existing:
        raise SystemExit(f"{target} exists; pass --replace-existing to overwrite it")
    payload = generate_execution_gate(output_dir)
    displayed = payload if args.verbose else {"validation_passed": payload["validation_passed"]}
    print(json.dumps(displayed, indent=2, sort_keys=True))
    return 0 if payload["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
