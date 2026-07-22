#!/usr/bin/env python3
"""Validate the frozen Stage 8 artifact without requiring the private Git commit."""

from pathlib import Path

from pqtrust_agent.campaigns.stage8 import Stage8Error, validate_run

FINAL_RUN_DIR = Path("runs/stage8/stage8-final-20260714-r2")


def main() -> int:
    if not FINAL_RUN_DIR.is_dir():
        print(f"[FAIL] Frozen Stage 8 run not found: {FINAL_RUN_DIR}")
        return 1

    try:
        result = validate_run(
            FINAL_RUN_DIR,
            write_report=False,
            repo=None,
        )
    except (OSError, KeyError, ValueError, Stage8Error) as exc:
        print(f"[FAIL] Frozen Stage 8 validation failed: {exc}")
        return 1

    if not bool(result.get("validation_passed", False)):
        print("[FAIL] Frozen Stage 8 campaign did not pass validation.")
        print("Errors:", result.get("validation_errors", []))
        return 1

    print("[PASS] Frozen Stage 8 campaign validated.")
    print("Expected counts:", result.get("expected_counts", {}))
    print("Observed counts:", result.get("observed_counts", {}))
    print("Validation errors:", result.get("validation_errors", []))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
