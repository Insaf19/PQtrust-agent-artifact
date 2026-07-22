"""Tracked Z3 unsat cores and deterministic deletion-based IUS shrinking."""

from __future__ import annotations

from dataclasses import dataclass

import z3

from pqtrust_agent.models.conflict import SHRINKING_ALGORITHM_VERSION, NamedConstraint
from pqtrust_agent.negotiation.conflict_constraints import (
    build_feasibility_model,
    solver_for_constraints,
)


@dataclass(frozen=True)
class IUSResult:
    original_constraint_count: int
    z3_unsat_core: tuple[NamedConstraint, ...]
    ius: tuple[NamedConstraint, ...]
    solver_call_count: int
    shrinking_algorithm: str = SHRINKING_ALGORITHM_VERSION

    @property
    def Z3_unsat_core_size(self) -> int:
        return len(self.z3_unsat_core)

    @property
    def IUS_size(self) -> int:
        return len(self.ius)


def compute_ius(
    *,
    profile_ids: tuple[str, ...],
    constraints: tuple[NamedConstraint, ...],
) -> IUSResult:
    ordered = tuple(sorted(constraints, key=lambda item: item.constraint_id))
    model = build_feasibility_model(profile_ids=profile_ids, constraints=ordered)
    solver = solver_for_constraints(model, tracked=True)
    solver_call_count = 1
    status = solver.check()
    if status != z3.unsat:
        raise ValueError("cannot compute conflict certificate for satisfiable model")
    label_to_constraint = {
        str(model.labels[constraint.constraint_id]): constraint for constraint in ordered
    }
    core = tuple(
        sorted(
            (label_to_constraint[str(label)] for label in solver.unsat_core()),
            key=lambda item: item.constraint_id,
        )
    )
    remaining = list(core)
    changed = True
    while changed:
        changed = False
        for constraint in tuple(remaining):
            trial = tuple(
                item for item in remaining if item.constraint_id != constraint.constraint_id
            )
            trial_model = build_feasibility_model(profile_ids=profile_ids, constraints=trial)
            trial_solver = solver_for_constraints(trial_model, tracked=False)
            solver_call_count += 1
            if trial_solver.check() == z3.unsat:
                remaining = list(trial)
                changed = True
                break
    return IUSResult(
        original_constraint_count=len(ordered),
        z3_unsat_core=core,
        ius=tuple(sorted(remaining, key=lambda item: item.constraint_id)),
        solver_call_count=solver_call_count,
    )


def verify_ius(
    *,
    profile_ids: tuple[str, ...],
    all_constraints: tuple[NamedConstraint, ...],
    ius: tuple[NamedConstraint, ...],
) -> list[str]:
    errors: list[str] = []
    all_ids = {constraint.constraint_id for constraint in all_constraints}
    ius_ids = [constraint.constraint_id for constraint in ius]
    if len(ius_ids) != len(set(ius_ids)):
        errors.append("duplicate constraint in IUS")
    unknown = sorted(set(ius_ids) - all_ids)
    if unknown:
        errors.append(f"IUS contains constraints outside model: {unknown}")
    model = build_feasibility_model(profile_ids=profile_ids, constraints=ius)
    if solver_for_constraints(model, tracked=False).check() != z3.unsat:
        errors.append("IUS constraint set is satisfiable")
        return errors
    for constraint in ius:
        remainder = tuple(item for item in ius if item.constraint_id != constraint.constraint_id)
        remainder_model = build_feasibility_model(profile_ids=profile_ids, constraints=remainder)
        if solver_for_constraints(remainder_model, tracked=False).check() != z3.sat:
            errors.append(f"IUS is not irreducible after removing {constraint.constraint_id}")
    return errors
