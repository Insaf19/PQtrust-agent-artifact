#!/usr/bin/env python3
"""Generate one deterministic Stage 7 session artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqtrust_agent.runtime.stage7_evidence import (
    FEASIBLE_SCENARIOS,
    INFEASIBLE_SCENARIOS,
    feasible_session,
    infeasible_session,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario_id", nargs="?", help="Stage 7 scenario id")
    parser.add_argument("--scenario", dest="scenario_option", help="Stage 7 scenario id")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/runtime"))
    parser.add_argument("--runtime-dir", type=Path, help="alias for --output-dir")
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    scenario_id = args.scenario_option or args.scenario_id
    if not scenario_id:
        parser.error("scenario id is required")
    repo = Path(__file__).resolve().parents[1]
    output_dir = args.runtime_dir or args.output_dir
    target = output_dir / (
        "feasible_sessions" if scenario_id in FEASIBLE_SCENARIOS else "infeasible_sessions"
    ) / f"{scenario_id}.json"
    if target.exists() and not args.replace_existing:
        raise SystemExit(f"{target} exists; pass --replace-existing to overwrite it")
    if scenario_id in FEASIBLE_SCENARIOS:
        payload = feasible_session(repo, output_dir, scenario_id)
    elif scenario_id in INFEASIBLE_SCENARIOS:
        payload = infeasible_session(repo, output_dir, scenario_id)
    else:
        raise SystemExit(f"unknown Stage 7 scenario: {scenario_id}")
    if args.verbose:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps({"scenario_id": scenario_id, "final_state": payload["final_state"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
