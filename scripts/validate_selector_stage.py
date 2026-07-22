#!/usr/bin/env python3
"""Validate Stage 4B bilateral minimax-regret selector scenarios."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from pqtrust_agent.evidence.decimal_json import dumps_decimal_json
from pqtrust_agent.negotiation.validation import validate_selector_stage


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(dumps_decimal_json(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def _write_outputs(output_dir: Path, reports: dict[str, dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in reports.items():
        _atomic_write_json(output_dir / name, payload)
    checksum_lines: list[str] = []
    for name in sorted(reports):
        path = output_dir / name
        checksum_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    checksum_path = output_dir / "checksums.sha256"
    tmp_path = checksum_path.with_name(".checksums.sha256.tmp")
    tmp_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    os.replace(tmp_path, checksum_path)
    expected = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0]
        for line in checksum_path.read_text(encoding="utf-8").splitlines()
        if line
    }
    for name, digest in expected.items():
        if hashlib.sha256((output_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"checksum verification failed for {name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("configs/profiles/trust_profiles.yaml"),
    )
    parser.add_argument("--agents-dir", type=Path, default=Path("configs/agents"))
    parser.add_argument("--policies-dir", type=Path, default=Path("configs/policies"))
    parser.add_argument("--preferences-dir", type=Path, default=Path("configs/preferences"))
    parser.add_argument("--scenarios-dir", type=Path, default=Path("configs/scenarios"))
    parser.add_argument(
        "--cost-evidence-dir",
        type=Path,
        default=Path("artifacts/paired-cost-calibration/r2-vs-confirmatory"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/selection/selector_stage_validation.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reports = validate_selector_stage(
        catalog_path=args.catalog,
        agents_dir=args.agents_dir,
        policies_dir=args.policies_dir,
        preferences_dir=args.preferences_dir,
        scenarios_dir=args.scenarios_dir,
        cost_evidence_dir=args.cost_evidence_dir,
    )
    output_dir = args.output.parent
    _write_outputs(output_dir, reports)
    main_report = reports["selector_stage_validation.json"]
    print(json.dumps(main_report, indent=2, sort_keys=True))
    return 0 if main_report["validation_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
