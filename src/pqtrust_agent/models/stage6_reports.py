"""Typed Stage 6 scientific validation reports."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from pqtrust_agent.models.conflict import ConflictCategory, HashHex, ProfileId


class Stage6ScenarioDiagnostics(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    capability_intersection_before_policy: tuple[ProfileId, ...]
    candidate_set_after_assurance_floor: tuple[ProfileId, ...]
    final_common_safe_set: tuple[ProfileId, ...]
    ius_categories: tuple[str, ...]
    task_minimum_lease_seconds: int | None = None
    agent_profile_maximum_lease_seconds: int | None = None
    otherwise_compatible_candidate_profiles: tuple[ProfileId, ...] = ()


class ConflictScenarioValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    certificate_hash: HashHex
    category: ConflictCategory
    IUS_size: Annotated[int, Field(ge=1)]
    verification_passed: bool
    validation_errors: tuple[str, ...]
    diagnostics: Stage6ScenarioDiagnostics


class ConflictStageValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: Literal["conflict_stage_validation"]
    report_version: Literal["1.0"] = "1.0"
    scenario_count: Annotated[int, Field(ge=0)]
    scenarios: tuple[ConflictScenarioValidation, ...]
    validation_errors: tuple[str, ...]
    validation_passed: bool


class SafeAbortScenarioValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    certificate_hash: HashHex
    failure_transcript_hash: HashHex
    abort_hash: HashHex
    selected_profile_id_is_null: bool
    contract_created_is_false: bool
    fallback_attempted_is_false: bool
    no_resumption: bool
    no_tls_profile_activation: bool
    certificate_verification_passed: bool
    failure_transcript_verification_passed: bool
    abort_hash_verification_passed: bool
    validation_passed: bool


class SafeAbortValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: Literal["safe_abort_validation"]
    report_version: Literal["1.0"] = "1.0"
    scenario_count: Annotated[int, Field(ge=0)]
    scenarios: tuple[SafeAbortScenarioValidation, ...]
    validation_errors: tuple[str, ...]
    validation_passed: bool


class FeasibleRegressionScenarioValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    selected_profile_before_stage6: ProfileId
    selected_profile_after_stage6: ProfileId
    selection_unchanged: bool
    original_signed_contract_hash: HashHex
    recomputed_signed_contract_hash: HashHex
    contract_hash_unchanged: bool
    conflict_certificate_produced: Literal[False]
    failure_transcript_produced: Literal[False]
    abort_record_produced: Literal[False]
    feasibility_remains_true: bool
    validation_passed: bool


class FeasibleRegressionValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: Literal["feasible_regression_validation"]
    report_version: Literal["1.0"] = "1.0"
    scenario_count: Annotated[int, Field(ge=0)]
    scenarios: tuple[FeasibleRegressionScenarioValidation, ...]
    validation_errors: tuple[str, ...]
    validation_passed: bool


class AdversarialCaseValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    attack_id: str
    target_scenario_id: str
    target_artifact_type: str
    mutation_applied: bool
    expected_rejection_code: str
    observed_rejection_code: str
    rejected: bool
    fail_closed: bool
    validation_passed: bool


class AdversarialConflictValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: Literal["adversarial_conflict_validation"]
    report_version: Literal["1.0"] = "1.0"
    case_count: Annotated[int, Field(ge=0)]
    attacks: tuple[AdversarialCaseValidation, ...]
    validation_errors: tuple[str, ...]
    validation_passed: bool


class Stage6BundleValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: Literal["stage6_bundle_validation"]
    report_version: Literal["1.0"] = "1.0"
    expected_infeasible_scenario_count: int
    generated_certificate_count: int
    generated_failure_transcript_count: int
    generated_abort_record_count: int
    generated_remediation_report_count: int
    safe_abort_scenario_count: int
    feasible_regression_scenario_count: int
    adversarial_case_count: int
    conflict_validation_passed: bool
    safe_abort_validation_passed: bool
    feasible_regression_passed: bool
    adversarial_validation_passed: bool
    taxonomy_validation_passed: bool
    cross_artifact_reference_validation_passed: bool
    checksum_validation_passed: bool
    report_content_hashes: dict[str, HashHex]
    validation_errors: tuple[str, ...]
    validation_passed: bool
