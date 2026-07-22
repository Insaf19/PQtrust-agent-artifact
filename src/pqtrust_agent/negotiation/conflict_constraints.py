"""Named Stage 6 constraints and finite-domain Z3 encoding."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import z3

from pqtrust_agent.models.conflict import (
    ConstraintSourceType,
    NamedConstraint,
    stable_constraint_id,
)


@dataclass(frozen=True)
class ConflictFeasibilityModel:
    selected_profile_index: z3.ArithRef
    profile_ids: tuple[str, ...]
    constraints: tuple[NamedConstraint, ...]
    expressions: dict[str, z3.BoolRef]
    labels: dict[str, z3.BoolRef]


def make_named_constraint(
    *,
    source_agent_id: str,
    source_type: ConstraintSourceType,
    category: str,
    attribute: str,
    operator: str,
    expected_value: object,
    profile_scope: Iterable[str],
    source_hash: str,
    human_explanation: str,
    negotiable: bool = False,
) -> NamedConstraint:
    scope = tuple(profile_scope)
    constraint_id = stable_constraint_id(
        source_agent_id=source_agent_id,
        source_type=source_type,
        category=category,
        attribute=attribute,
        operator=operator,
        expected_value=expected_value,
        profile_scope=scope,
        source_hash=source_hash,
    )
    return NamedConstraint(
        constraint_id=constraint_id,
        source_agent_id=source_agent_id,
        source_type=source_type,
        category=category,
        attribute=attribute,
        operator=operator,
        expected_value=expected_value,
        profile_scope=scope,
        hard=True,
        negotiable=negotiable,
        source_hash=source_hash,
        human_explanation=human_explanation,
    )


def local_safe_set_constraints(
    *,
    initiator_agent_id: str,
    responder_agent_id: str,
    initiator_safe_set: tuple[str, ...],
    responder_safe_set: tuple[str, ...],
    initiator_compilation_hash: str,
    responder_compilation_hash: str,
) -> tuple[NamedConstraint, NamedConstraint]:
    return (
        make_named_constraint(
            source_agent_id=initiator_agent_id,
            source_type=ConstraintSourceType.PRIVATE_POLICY,
            category="profile_support",
            attribute="selected_profile_id",
            operator="in",
            expected_value=initiator_safe_set,
            profile_scope=initiator_safe_set,
            source_hash=initiator_compilation_hash,
            human_explanation="Initiator hard policy permits only the disclosed safe profiles.",
        ),
        make_named_constraint(
            source_agent_id=responder_agent_id,
            source_type=ConstraintSourceType.PRIVATE_POLICY,
            category="profile_support",
            attribute="selected_profile_id",
            operator="in",
            expected_value=responder_safe_set,
            profile_scope=responder_safe_set,
            source_hash=responder_compilation_hash,
            human_explanation="Responder hard policy permits only the disclosed safe profiles.",
        ),
    )


def build_feasibility_model(
    *,
    profile_ids: tuple[str, ...],
    constraints: tuple[NamedConstraint, ...],
) -> ConflictFeasibilityModel:
    selected = z3.Int("pqtrust.conflict.v1.selected_profile_index")
    expressions: dict[str, z3.BoolRef] = {}
    labels: dict[str, z3.BoolRef] = {}
    seen: set[str] = set()
    for constraint in constraints:
        if constraint.constraint_id in seen:
            raise ValueError(f"duplicate constraint: {constraint.constraint_id}")
        seen.add(constraint.constraint_id)
        allowed_indexes = tuple(
            index
            for index, profile_id in enumerate(profile_ids)
            if profile_id in constraint.profile_scope
        )
        expressions[constraint.constraint_id] = _scope_expression(selected, allowed_indexes)
        labels[constraint.constraint_id] = z3.Bool(
            f"pqtrust.conflict.v1.{constraint.constraint_id}"
        )
    return ConflictFeasibilityModel(
        selected_profile_index=selected,
        profile_ids=profile_ids,
        constraints=constraints,
        expressions=expressions,
        labels=labels,
    )


def solver_for_constraints(
    model: ConflictFeasibilityModel,
    constraints: tuple[NamedConstraint, ...] | None = None,
    *,
    tracked: bool,
) -> z3.Solver:
    solver = z3.Solver()
    solver.add(model.selected_profile_index >= 0)
    solver.add(model.selected_profile_index < len(model.profile_ids))
    active = constraints if constraints is not None else model.constraints
    for constraint in active:
        expression = model.expressions[constraint.constraint_id]
        if tracked:
            solver.assert_and_track(expression, model.labels[constraint.constraint_id])
        else:
            solver.add(expression)
    return solver


def satisfiable_profile_ids(
    *,
    profile_ids: tuple[str, ...],
    constraints: tuple[NamedConstraint, ...],
) -> tuple[str, ...]:
    model = build_feasibility_model(profile_ids=profile_ids, constraints=constraints)
    possible: list[str] = []
    for index, profile_id in enumerate(profile_ids):
        solver = solver_for_constraints(model, tracked=False)
        solver.add(model.selected_profile_index == index)
        if solver.check() == z3.sat:
            possible.append(profile_id)
    return tuple(possible)


def _scope_expression(selected: z3.ArithRef, allowed_indexes: tuple[int, ...]) -> z3.BoolRef:
    if not allowed_indexes:
        return z3.BoolVal(False)
    return z3.Or(*(selected == index for index in allowed_indexes))
