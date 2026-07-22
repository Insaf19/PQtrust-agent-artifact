"""Trusted loader for calibrated TLS selector-cost evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from pqtrust_agent.evidence.decimal_json import load_decimal_json
from pqtrust_agent.exceptions import PQTrustError
from pqtrust_agent.models.catalog import ProfileCatalog

MetricName = Literal["wall_time", "process_cpu_time", "total_handshake_bytes"]
METRICS: tuple[MetricName, ...] = ("wall_time", "process_cpu_time", "total_handshake_bytes")
EXPECTED_PROFILE_IDS = ("P0", "P1", "P2", "P3", "P4")
EXPECTED_COMPLETE_PAIRED_BLOCKS = 1200
EXPECTED_SOURCE_RUN_IDS = ("calibration-20260713-r2", "calibration-20260713-confirmatory")


class CostEvidenceError(PQTrustError, ValueError):
    """Raised when selector cost evidence is missing, corrupt, or unusable."""


@dataclass(frozen=True)
class BootstrapInterval:
    lower: Decimal
    upper: Decimal
    confidence_level: Decimal
    iterations: int
    seed: int


@dataclass(frozen=True)
class ProfileCostEvidence:
    profile_id: str
    tls_group: str
    wall_time: Decimal
    process_cpu_time: Decimal
    total_handshake_bytes: Decimal
    wall_time_interval: BootstrapInterval
    process_cpu_time_interval: BootstrapInterval
    catalog_hash: str
    scientific_design_hash: str
    source_run_ids: tuple[str, ...]
    source_raw_checksums: dict[str, str]

    def measured_vector(self, case: str = "point") -> dict[MetricName, Decimal]:
        if case == "point":
            return {
                "wall_time": self.wall_time,
                "process_cpu_time": self.process_cpu_time,
                "total_handshake_bytes": self.total_handshake_bytes,
            }
        if case == "lower":
            return {
                "wall_time": self.wall_time_interval.lower,
                "process_cpu_time": self.process_cpu_time_interval.lower,
                "total_handshake_bytes": self.total_handshake_bytes,
            }
        if case == "upper":
            return {
                "wall_time": self.wall_time_interval.upper,
                "process_cpu_time": self.process_cpu_time_interval.upper,
                "total_handshake_bytes": self.total_handshake_bytes,
            }
        raise CostEvidenceError(f"unknown cost case: {case}")


@dataclass(frozen=True)
class SelectorCostEvidence:
    profiles: tuple[ProfileCostEvidence, ...]
    evidence_hash: str
    selector_file_sha256: str
    quality_gate_file_sha256: str
    analysis_manifest_file_sha256: str
    catalog_hash: str
    scientific_design_hash: str
    source_raw_checksums: dict[str, str]
    source_run_ids: tuple[str, ...]
    absolute_timing_stability_passed: bool
    paired_relative_timing_stability_passed: bool
    relative_cost_usable_for_selector: bool
    complete_paired_blocks: int

    def by_profile(self) -> dict[str, ProfileCostEvidence]:
        return {profile.profile_id: profile for profile in self.profiles}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_checksums(directory: Path) -> dict[str, str]:
    checksum_path = directory / "checksums.sha256"
    if not checksum_path.exists():
        raise CostEvidenceError(f"missing checksum manifest: {checksum_path}")
    verified: dict[str, str] = {}
    for line_number, line in enumerate(checksum_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise CostEvidenceError(f"invalid checksum line {line_number}: {line}")
        expected, relative = parts
        if "/" in relative or relative.startswith("."):
            raise CostEvidenceError(f"unsafe checksum path: {relative}")
        path = directory / relative
        if not path.exists():
            raise CostEvidenceError(f"checksummed file is missing: {relative}")
        actual = _sha256_file(path)
        if actual != expected:
            raise CostEvidenceError(f"checksum mismatch for {relative}: {actual} != {expected}")
        verified[relative] = actual
    for required in (
        "selector_tls_cost_evidence.json",
        "relative_cost_quality_gate.json",
        "analysis_manifest.json",
    ):
        if required not in verified:
            raise CostEvidenceError(f"checksum manifest does not cover {required}")
    return verified


def _as_decimal(value: Any, field: str, *, positive: bool = True) -> Decimal:
    if not isinstance(value, Decimal | int):
        raise CostEvidenceError(f"{field} must be a JSON number")
    decimal = Decimal(value)
    if not decimal.is_finite():
        raise CostEvidenceError(f"{field} must be finite")
    if decimal < 0 or (positive and decimal == 0):
        raise CostEvidenceError(f"{field} must be {'positive' if positive else 'non-negative'}")
    return decimal


def _as_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - set("0123456789abcdef"):
        raise CostEvidenceError(f"{field} must be a lowercase sha256 hex digest")
    return value


def _parse_interval(raw: Any, field: str) -> BootstrapInterval:
    if not isinstance(raw, dict):
        raise CostEvidenceError(f"{field} must be an object")
    lower = _as_decimal(raw.get("lower"), f"{field}.lower")
    upper = _as_decimal(raw.get("upper"), f"{field}.upper")
    if lower > upper:
        raise CostEvidenceError(f"{field} lower bound exceeds upper bound")
    iterations = raw.get("iterations")
    seed = raw.get("seed")
    if not isinstance(iterations, int) or iterations <= 0:
        raise CostEvidenceError(f"{field}.iterations must be positive")
    if not isinstance(seed, int):
        raise CostEvidenceError(f"{field}.seed must be an integer")
    return BootstrapInterval(
        lower=lower,
        upper=upper,
        confidence_level=_as_decimal(raw.get("confidence_level"), f"{field}.confidence_level"),
        iterations=iterations,
        seed=seed,
    )


def _validate_gate(raw: Any, catalog: ProfileCatalog) -> tuple[bool, bool, bool, int]:
    if not isinstance(raw, dict):
        raise CostEvidenceError("quality gate must be an object")
    usable = raw.get("relative_cost_usable_for_selector")
    relative = raw.get("paired_relative_timing_stability_passed")
    absolute = raw.get("absolute_timing_stability_passed")
    blocks = raw.get("complete_paired_blocks")
    if usable is not True:
        raise CostEvidenceError("relative_cost_usable_for_selector must be true")
    if relative is not True:
        raise CostEvidenceError("paired_relative_timing_stability_passed must be true")
    if absolute is not False:
        raise CostEvidenceError("absolute_timing_stability_passed=false must remain visible")
    if blocks != EXPECTED_COMPLETE_PAIRED_BLOCKS:
        raise CostEvidenceError("complete_paired_blocks must be 1200")
    profile_gates = raw.get("profile_gates")
    if not isinstance(profile_gates, dict) or tuple(sorted(profile_gates)) != EXPECTED_PROFILE_IDS:
        raise CostEvidenceError("quality gate must contain exactly P0-P4 profile gates")
    catalog_groups = {profile.profile_id: profile.tls_group for profile in catalog.profiles}
    for profile_id, gate in profile_gates.items():
        if not isinstance(gate, dict):
            raise CostEvidenceError(f"{profile_id} gate must be an object")
        if gate.get("paired_relative_timing_stability_passed") is not True:
            raise CostEvidenceError(f"{profile_id} did not pass paired timing stability")
        if gate.get("tls_group") != catalog_groups.get(profile_id):
            raise CostEvidenceError(f"{profile_id} TLS group mismatch in quality gate")
    return absolute, relative, usable, blocks


def _validate_manifest(raw: Any, catalog_hash: str) -> tuple[str, dict[str, str], tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise CostEvidenceError("analysis manifest must be an object")
    compatibility = raw.get("compatibility")
    integrity = raw.get("integrity")
    source_raw_checksums = raw.get("source_raw_checksums")
    if (
        not isinstance(compatibility, dict)
        or compatibility.get("comparison_compatible") is not True
    ):
        raise CostEvidenceError("scientific compatibility must pass")
    if compatibility.get("catalog_hashes_match") is not True:
        raise CostEvidenceError("catalog hashes must match across runs")
    if compatibility.get("scientific_design_hashes_match") is not True:
        raise CostEvidenceError("scientific design hashes must match")
    if not isinstance(integrity, dict):
        raise CostEvidenceError("analysis manifest integrity section is missing")
    for label in ("baseline", "confirmatory"):
        item = integrity.get(label)
        if not isinstance(item, dict) or item.get("validation_passed") is not True:
            raise CostEvidenceError(f"{label} raw integrity did not pass")
        checks = item.get("checks")
        if not isinstance(checks, dict) or checks.get("raw_checksums_valid") is not True:
            raise CostEvidenceError(f"{label} raw checksum validation did not pass")
    catalog_pair = compatibility.get("details", {}).get("catalog_hash", {})
    if (
        catalog_pair.get("baseline") != catalog_hash
        or catalog_pair.get("confirmatory") != catalog_hash
    ):
        raise CostEvidenceError("analysis manifest catalog hash does not match current catalog")
    scientific_hash = compatibility.get("baseline_scientific_design_hash")
    if scientific_hash != compatibility.get("confirmatory_scientific_design_hash"):
        raise CostEvidenceError("scientific design hash mismatch")
    scientific_hash = _as_hash(scientific_hash, "scientific_design_hash")
    if not isinstance(source_raw_checksums, dict):
        raise CostEvidenceError("analysis manifest source_raw_checksums is missing")
    checksums = {
        str(key): _as_hash(value, f"source_raw_checksums.{key}")
        for key, value in source_raw_checksums.items()
    }
    if tuple(sorted(checksums)) != tuple(sorted(EXPECTED_SOURCE_RUN_IDS)):
        raise CostEvidenceError("unexpected source run IDs")
    return scientific_hash, checksums, EXPECTED_SOURCE_RUN_IDS


def _parse_profiles(
    raw: Any,
    catalog: ProfileCatalog,
    manifest_checksums: dict[str, str],
) -> tuple[ProfileCostEvidence, ...]:
    if (
        not isinstance(raw, dict)
        or raw.get("artifact_type") != "calibrated_tls_selector_cost_evidence"
    ):
        raise CostEvidenceError("selector evidence has unexpected artifact_type")
    profiles = raw.get("profiles")
    if not isinstance(profiles, list):
        raise CostEvidenceError("selector evidence profiles must be a list")
    if len(profiles) != len(EXPECTED_PROFILE_IDS):
        raise CostEvidenceError("selector evidence must contain exactly P0-P4")
    catalog_groups = {profile.profile_id: profile.tls_group for profile in catalog.profiles}
    seen: set[str] = set()
    parsed: list[ProfileCostEvidence] = []
    for item in profiles:
        if not isinstance(item, dict):
            raise CostEvidenceError("profile evidence entry must be an object")
        profile_id = str(item.get("profile_id"))
        if profile_id not in EXPECTED_PROFILE_IDS:
            raise CostEvidenceError(f"unknown profile in selector evidence: {profile_id}")
        if profile_id in seen:
            raise CostEvidenceError(f"duplicate profile in selector evidence: {profile_id}")
        seen.add(profile_id)
        if item.get("tls_group") != catalog_groups.get(profile_id):
            raise CostEvidenceError(f"{profile_id} TLS group mismatch")
        if item.get("catalog_hash") != catalog.catalog_hash():
            raise CostEvidenceError(f"{profile_id} catalog hash mismatch")
        runs = item.get("source_run_ids")
        if not isinstance(runs, list) or tuple(runs) != EXPECTED_SOURCE_RUN_IDS:
            raise CostEvidenceError(f"{profile_id} source run IDs mismatch")
        raw_checksums = item.get("source_raw_checksums")
        if not isinstance(raw_checksums, dict) or raw_checksums != manifest_checksums:
            raise CostEvidenceError(f"{profile_id} source raw checksums mismatch")
        usability = item.get("usability_status")
        if (
            not isinstance(usability, dict)
            or usability.get("paired_relative_timing_stability_passed") is not True
        ):
            raise CostEvidenceError(f"{profile_id} paired timing usability did not pass")
        parsed.append(
            ProfileCostEvidence(
                profile_id=profile_id,
                tls_group=str(item["tls_group"]),
                wall_time=_as_decimal(
                    item.get("wall_time_relative_estimate"),
                    f"{profile_id}.wall_time",
                ),
                process_cpu_time=_as_decimal(
                    item.get("cpu_time_relative_estimate"),
                    f"{profile_id}.process_cpu_time",
                ),
                total_handshake_bytes=_as_decimal(
                    item.get("total_handshake_byte_relative_estimate"),
                    f"{profile_id}.total_handshake_bytes",
                ),
                wall_time_interval=_parse_interval(
                    item.get("wall_time_paired_bootstrap_interval"),
                    f"{profile_id}.wall_time_interval",
                ),
                process_cpu_time_interval=_parse_interval(
                    item.get("cpu_time_paired_bootstrap_interval"),
                    f"{profile_id}.process_cpu_time_interval",
                ),
                catalog_hash=str(item["catalog_hash"]),
                scientific_design_hash=_as_hash(
                    item.get("scientific_design_hash"),
                    f"{profile_id}.scientific_design_hash",
                ),
                source_run_ids=tuple(str(run) for run in runs),
                source_raw_checksums={str(key): str(value) for key, value in raw_checksums.items()},
            )
        )
    if tuple(sorted(seen)) != EXPECTED_PROFILE_IDS:
        raise CostEvidenceError("selector evidence must contain exactly P0-P4")
    return tuple(sorted(parsed, key=lambda profile: profile.profile_id))


def load_selector_cost_evidence(directory: Path, catalog: ProfileCatalog) -> SelectorCostEvidence:
    """Verify checksums and load calibrated TLS selector-cost evidence."""

    verified = _verify_checksums(directory)
    selector_raw = load_decimal_json(directory / "selector_tls_cost_evidence.json")
    gate_raw = load_decimal_json(directory / "relative_cost_quality_gate.json")
    manifest_raw = load_decimal_json(directory / "analysis_manifest.json")
    if catalog.profile_ids() != EXPECTED_PROFILE_IDS:
        raise CostEvidenceError("current catalog must contain exactly P0-P4")
    absolute, relative, usable, blocks = _validate_gate(gate_raw, catalog)
    scientific_hash, source_checksums, source_run_ids = _validate_manifest(
        manifest_raw, catalog.catalog_hash()
    )
    profiles = _parse_profiles(selector_raw, catalog, source_checksums)
    if {profile.scientific_design_hash for profile in profiles} != {scientific_hash}:
        raise CostEvidenceError("profile scientific-design hash mismatch")
    return SelectorCostEvidence(
        profiles=profiles,
        evidence_hash=verified["selector_tls_cost_evidence.json"],
        selector_file_sha256=verified["selector_tls_cost_evidence.json"],
        quality_gate_file_sha256=verified["relative_cost_quality_gate.json"],
        analysis_manifest_file_sha256=verified["analysis_manifest.json"],
        catalog_hash=catalog.catalog_hash(),
        scientific_design_hash=scientific_hash,
        source_raw_checksums=source_checksums,
        source_run_ids=source_run_ids,
        absolute_timing_stability_passed=absolute,
        paired_relative_timing_stability_passed=relative,
        relative_cost_usable_for_selector=usable,
        complete_paired_blocks=blocks,
    )
