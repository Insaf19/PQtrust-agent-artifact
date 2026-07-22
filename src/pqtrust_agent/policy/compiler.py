"""Local deterministic policy compiler."""

from __future__ import annotations

from datetime import datetime

import z3

from pqtrust_agent.exceptions import PolicyCompilationError
from pqtrust_agent.models.catalog import ProfileCatalog
from pqtrust_agent.models.compilation import (
    COMPILER_IMPLEMENTATION_VERSION,
    POLICY_COMPILATION_HASH_DOMAIN,
    REJECTION_CATEGORY_ORDER,
    PolicyCompilationResult,
    ProfileCompilationDecision,
    RejectionCategory,
    compilation_hash,
    sort_rejection_categories,
)
from pqtrust_agent.models.manifest import CapabilityManifestPayload
from pqtrust_agent.models.policy import AgentPolicy
from pqtrust_agent.models.task import TaskDescriptor
from pqtrust_agent.policy.mapper import derive_requirement
from pqtrust_agent.policy.validation import validate_compilation_inputs
from pqtrust_agent.policy.z3_encoding import (
    ConstraintEncoding,
    build_constraint_encoding,
    profile_violated_categories,
)


def _new_solver(timeout_ms: int) -> z3.Solver:
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    return solver


def _assert_encoding(solver: z3.Solver, encoding: ConstraintEncoding) -> None:
    for category, constraint in encoding.constraints.items():
        solver.add(z3.Implies(encoding.labels[category], constraint))


def _check_status(solver: z3.Solver, assumptions: list[z3.BoolRef]) -> str:
    status = solver.check(*assumptions)
    if status == z3.sat:
        return "sat"
    if status == z3.unsat:
        return "unsat"
    raise PolicyCompilationError("Z3 returned unknown")


def _canonical_categories() -> tuple[RejectionCategory, ...]:
    ordered = sorted(
        REJECTION_CATEGORY_ORDER,
        key=lambda item: REJECTION_CATEGORY_ORDER[item],
    )
    return tuple(
        category
        for category in ordered
        if category is not RejectionCategory.RESOURCE_BOUND
    )


def _minimize_core(
    catalog: ProfileCatalog,
    manifest: CapabilityManifestPayload,
    policy: AgentPolicy,
    task: TaskDescriptor,
    profile_index: int,
    categories: tuple[RejectionCategory, ...],
) -> tuple[RejectionCategory, ...]:
    derivation = derive_requirement(policy, task)
    encoding = build_constraint_encoding(
        catalog,
        manifest,
        policy,
        task,
        derivation.final_requirement,
    )
    remaining = list(categories)
    for category in _canonical_categories():
        if category not in remaining:
            continue
        trial = [item for item in remaining if item != category]
        solver = _new_solver(policy.solver_timeout_ms)
        _assert_encoding(solver, encoding)
        solver.add(encoding.selected_profile_index == profile_index)
        assumptions = [encoding.labels[item] for item in trial]
        if _check_status(solver, assumptions) == "unsat":
            remaining = trial
    return sort_rejection_categories(tuple(remaining))


def _candidate_status(
    catalog: ProfileCatalog,
    manifest: CapabilityManifestPayload,
    policy: AgentPolicy,
    task: TaskDescriptor,
    profile_index: int,
) -> str:
    derivation = derive_requirement(policy, task)
    encoding = build_constraint_encoding(
        catalog,
        manifest,
        policy,
        task,
        derivation.final_requirement,
    )
    solver = _new_solver(policy.solver_timeout_ms)
    _assert_encoding(solver, encoding)
    solver.add(encoding.selected_profile_index == profile_index)
    assumptions = [encoding.labels[category] for category in _canonical_categories()]
    return _check_status(solver, assumptions)


def compile_local_policy(
    catalog: ProfileCatalog,
    manifest: CapabilityManifestPayload,
    policy: AgentPolicy,
    task: TaskDescriptor,
    evaluation_time: datetime,
) -> PolicyCompilationResult:
    """Compile one agent's local safe profile set."""

    normalized_time = validate_compilation_inputs(catalog, manifest, policy, evaluation_time)
    derivation = derive_requirement(policy, task)
    encoding = build_constraint_encoding(
        catalog,
        manifest,
        policy,
        task,
        derivation.final_requirement,
    )
    assumptions = [encoding.labels[category] for category in _canonical_categories()]
    solver = _new_solver(policy.solver_timeout_ms)
    _assert_encoding(solver, encoding)

    enumerated_indexes: list[int] = []
    while True:
        status = _check_status(solver, assumptions)
        if status == "unsat":
            break
        model = solver.model()
        value = model.eval(encoding.selected_profile_index, model_completion=True)
        if not isinstance(value, z3.IntNumRef):
            raise PolicyCompilationError("selected profile index was not concrete")
        profile_index = value.as_long()
        enumerated_indexes.append(profile_index)
        solver.add(encoding.selected_profile_index != profile_index)

    decisions: list[ProfileCompilationDecision] = []
    independently_accepted: list[int] = []
    for index, profile in enumerate(catalog.profiles):
        status = _candidate_status(catalog, manifest, policy, task, index)
        if status == "sat":
            independently_accepted.append(index)
            decisions.append(
                ProfileCompilationDecision(
                    profile_id=profile.profile_id,
                    accepted=True,
                    violated_categories=(),
                    irreducible_unsat_core=(),
                    solver_status="sat",
                )
            )
        else:
            violated = sort_rejection_categories(
                profile_violated_categories(
                    profile,
                    manifest,
                    policy,
                    task,
                    derivation.final_requirement,
                )
            )
            if not violated:
                raise PolicyCompilationError(
                    f"candidate {profile.profile_id} is unsat without public violations"
                )
            core = _minimize_core(catalog, manifest, policy, task, index, violated)
            decisions.append(
                ProfileCompilationDecision(
                    profile_id=profile.profile_id,
                    accepted=False,
                    violated_categories=violated,
                    irreducible_unsat_core=core,
                    solver_status="unsat",
                )
            )

    if tuple(sorted(enumerated_indexes)) != tuple(independently_accepted):
        raise PolicyCompilationError("Z3 enumeration and independent candidate checks differ")

    safe_profile_ids = tuple(catalog.profiles[index].profile_id for index in independently_accepted)
    hash_payload = PolicyCompilationResult.compute_hash_payload(
        compiler_schema_version="1.0",
        compiler_implementation_version=COMPILER_IMPLEMENTATION_VERSION,
        z3_version=z3.get_version_string(),
        agent_id=policy.agent_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_hash=policy.policy_hash(),
        manifest_hash=manifest.manifest_hash(),
        task_hash=task.context_hash(),
        catalog_hash=catalog.catalog_hash(),
        evaluation_time=normalized_time,
        requirement_derivation=derivation,
        safe_profile_ids=safe_profile_ids,
        profile_decisions=tuple(decisions),
        solver_timeout_ms=policy.solver_timeout_ms,
    )
    return PolicyCompilationResult(
        compiler_schema_version="1.0",
        compiler_implementation_version=COMPILER_IMPLEMENTATION_VERSION,
        z3_version=z3.get_version_string(),
        agent_id=policy.agent_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_hash=policy.policy_hash(),
        manifest_hash=manifest.manifest_hash(),
        task_hash=task.context_hash(),
        catalog_hash=catalog.catalog_hash(),
        evaluation_time=normalized_time,
        requirement_derivation=derivation,
        safe_profile_ids=safe_profile_ids,
        profile_decisions=tuple(decisions),
        solver_timeout_ms=policy.solver_timeout_ms,
        compilation_hash=compilation_hash(hash_payload),
    )


__all__ = [
    "POLICY_COMPILATION_HASH_DOMAIN",
    "compile_local_policy",
]
