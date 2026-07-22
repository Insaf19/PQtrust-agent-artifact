#!/usr/bin/env python3
"""Read-only validation of the public Stage 9 artifact.

Rendered diagnostic figures are intentionally omitted. Their source data,
metadata, captions, provenance records, and checksums remain validated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from pqtrust_agent.analysis.stage9 import (
    ANALYSIS_DIR,
    EXPECTED_FIGURES,
    EXPECTED_TABLES,
    read_json,
    validate_claim_ledger,
    verify_checksums,
    verify_stage8_inputs,
)

STATISTICS_REQUIRED = (
    "analysis_validation.json",
    "descriptive_statistics.csv",
    "paired_comparisons.csv",
    "bootstrap_intervals.csv",
    "multiple_comparison_correction.csv",
    "fairness_analysis.json",
    "infeasible_analysis.json",
    "adversarial_analysis.json",
    "concurrency_analysis.json",
    "component_analysis.json",
    "assumptions_and_diagnostics.json",
    "checksums.sha256",
)

FIGURE_DATA_REQUIRED = (
    "data.json",
    "metadata.json",
    "caption.txt",
    "provenance.json",
    "checksums.sha256",
)


def validate_statistics(output_dir: Path) -> list[str]:
    errors: list[str] = []
    statistics_dir = output_dir / "statistics"

    for name in STATISTICS_REQUIRED:
        if not (statistics_dir / name).is_file():
            errors.append(f"missing statistics file: {name}")

    if (statistics_dir / "checksums.sha256").is_file():
        errors.extend(verify_checksums(statistics_dir))

    claim_ledger = output_dir / "claim_ledger.json"
    if claim_ledger.is_file():
        errors.extend(validate_claim_ledger(read_json(claim_ledger)))
    else:
        errors.append("missing claim ledger")

    return errors


def validate_figure_data(output_dir: Path) -> list[str]:
    errors: list[str] = []
    figure_data_dir = output_dir / "figure_data"

    for figure_id in EXPECTED_FIGURES:
        package = figure_data_dir / figure_id

        if not package.is_dir():
            errors.append(f"missing figure-data package: {figure_id}")
            continue

        for name in FIGURE_DATA_REQUIRED:
            if not (package / name).is_file():
                errors.append(f"missing {figure_id}/{name}")

        caption = package / "caption.txt"
        if caption.is_file() and not caption.read_text(encoding="utf-8").strip():
            errors.append(f"empty caption: {figure_id}")

        if (package / "checksums.sha256").is_file():
            errors.extend(
                f"{figure_id}: {error}"
                for error in verify_checksums(package)
            )

    return errors


def validate_tables(output_dir: Path) -> list[str]:
    errors: list[str] = []
    tables_dir = output_dir / "tables"

    if not tables_dir.is_dir():
        return ["missing tables directory"]

    for table_id in EXPECTED_TABLES:
        expected_files = (
            f"{table_id}.csv",
            f"{table_id}.tex",
            f"{table_id}.provenance.json",
        )
        for name in expected_files:
            if not (tables_dir / name).is_file():
                errors.append(f"missing table file: {name}")

    if (tables_dir / "checksums.sha256").is_file():
        errors.extend(verify_checksums(tables_dir))
    else:
        errors.append("missing tables/checksums.sha256")

    return errors


def main() -> int:
    errors: list[str] = []

    stage8_result = verify_stage8_inputs()
    errors.extend(
        cast(list[str], stage8_result.get("validation_errors", []))
    )

    errors.extend(validate_statistics(ANALYSIS_DIR))
    errors.extend(validate_figure_data(ANALYSIS_DIR))
    errors.extend(validate_tables(ANALYSIS_DIR))
    errors.extend(verify_checksums(ANALYSIS_DIR))

    result: dict[str, Any] = {
        "artifact": "stage9_public_artifact_validation",
        "rendered_figures_included": False,
        "figure_data_packages_expected": len(EXPECTED_FIGURES),
        "table_packages_expected": len(EXPECTED_TABLES),
        "validation_errors": errors,
        "validation_passed": not errors,
    }

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
