#!/usr/bin/env python3
"""Technical preflight for Stage 8 production measurement adapters."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from pqtrust_agent.campaigns.stage8 import write_json
from pqtrust_agent.campaigns.stage8_measurement import (
    measure_dispatch,
    validate_observation_row,
    warm_up_tls_groups,
)
from pqtrust_agent.runtime.stage7_evidence import ADVERSARIAL_CASES
from pqtrust_agent.tls_groups import require_matching_tls_groups


def _schedule() -> list[dict[str, Any]]:
    return [
        {
            "order": 0,
            "kind": "feasible",
            "observation_id": "technical-preflight:feasible",
            "scenario_id": "low-risk-public-tool",
            "method": "bilateral_minimax_regret",
            "block_id": 0,
            "repetition": 0,
            "paired_comparison_id": "technical-preflight",
        },
        {
            "order": 1,
            "kind": "infeasible",
            "observation_id": "technical-preflight:infeasible",
            "scenario_id": "no-common-profile",
            "repetition": 0,
        },
        {
            "order": 2,
            "kind": "adversarial",
            "observation_id": "technical-preflight:adversarial",
            "attack_id": str(ADVERSARIAL_CASES[0]["case_id"]),
            "trial": 0,
        },
        {
            "order": 3,
            "kind": "concurrency",
            "observation_id": "technical-preflight:concurrency",
            "scenario_id": "low-risk-public-tool",
            "requested_concurrency": 2,
            "repetition": 0,
        },
        {
            "order": 4,
            "kind": "component",
            "observation_id": "technical-preflight:component",
            "component": "ML-DSA-65_signing_and_verification",
            "process_index": 0,
            "operations": 2,
        },
    ]


def _assert_temp_only(path: Path) -> None:
    resolved = path.resolve()
    forbidden = [
        Path("runs/stage8").resolve(),
        Path("artifacts/campaigns/final").resolve(),
    ]
    for root in forbidden:
        if resolved == root or root in resolved.parents:
            raise ValueError(f"technical preflight cannot write into {root}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="keep the temporary preflight directory for debugging",
    )
    args = parser.parse_args()
    repo = args.repo.resolve()
    temp = tempfile.TemporaryDirectory(prefix="pqtrust-stage8-adapter-preflight-")
    temp_path = Path(temp.name)
    try:
        _assert_temp_only(temp_path)
        run_dir = temp_path / "run"
        (run_dir / "raw").mkdir(parents=True)
        write_json(
            run_dir / "manifest.json",
            {
                "artifact": "stage8_measurement_adapter_technical_preflight_manifest",
                "technical_preflight": True,
                "campaign_run_id": "technical-preflight",
                "campaign_design_hash": "0" * 64,
                "registration_commit": "technical-preflight",
                "registration_artifact_hash": "0" * 64,
                "schedule_hash": "0" * 64,
            },
        )
        warmup = warm_up_tls_groups(repo, ["X25519"])
        rows = []
        errors = []
        for scheduled in _schedule():
            row = measure_dispatch(
                repo,
                run_dir,
                scheduled,
                adversarial_cases=ADVERSARIAL_CASES,
            )
            row["technical_preflight"] = True
            try:
                validate_observation_row(row)
            except Exception as exc:
                errors.append(f"{scheduled['observation_id']}: {exc}")
            rows.append(row)
        errors.extend(_preflight_invariant_errors(rows))
        report = {
            "artifact": "stage8_measurement_adapter_technical_preflight",
            "technical_preflight": True,
            "temporary_directory": str(temp_path),
            "warmup": warmup,
            "rows": rows,
            "validation_errors": errors,
            "validation_passed": not errors,
        }
        write_json(run_dir / "technical_preflight_report.json", report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["validation_passed"] else 1
    finally:
        if args.keep_temp:
            print(json.dumps({"kept_temp_dir": str(temp_path)}, sort_keys=True))
        else:
            temp.cleanup()


def _tls_groups_match(row: dict[str, Any]) -> bool:
    try:
        require_matching_tls_groups(
            requested=str(row.get("requested_tls_group")),
            negotiated=str(row.get("negotiated_tls_group")),
        )
    except ValueError:
        return False
    return True


def _preflight_invariant_errors(rows: list[dict[str, Any]]) -> list[str]:
    invariants = {
        "feasible": any(
            row["kind"] == "feasible"
            and row.get("completed") is True
            and row.get("final_state") == "COMPLETED"
            and _tls_groups_match(row)
            for row in rows
        ),
        "infeasible": any(
            row["kind"] == "infeasible"
            and row.get("completed") is True
            and row.get("final_state") == "ABORTED"
            and row.get("TLS_invoked") is False
            and row.get("task_invoked") is False
            for row in rows
        ),
        "adversarial": any(
            row["kind"] == "adversarial"
            and row.get("rejected") is True
            and row.get("expected_rejection_code") == row.get("observed_rejection_code")
            for row in rows
        ),
        "concurrency": any(
            row["kind"] == "concurrency"
            and row.get("requested_concurrency") == 2
            and row.get("successful_sessions") == 2
            and row.get("failed_sessions") == 0
            and row.get("completed") is True
            for row in rows
        ),
        "component": any(
            row["kind"] == "component"
            and row.get("completed") is True
            and row.get("operation_count") == 2
            for row in rows
        ),
    }
    return [
        f"technical preflight invariant failed: {name}"
        for name, passed in invariants.items()
        if not passed
    ]


if __name__ == "__main__":
    raise SystemExit(main())
