"""Deterministic task-to-requirement mapper."""

from __future__ import annotations

from pqtrust_agent.models.compilation import RequirementDerivation, derivation_hash
from pqtrust_agent.models.policy import AgentPolicy
from pqtrust_agent.models.requirements import AssuranceRequirement
from pqtrust_agent.models.task import TaskDescriptor


def derive_requirement(policy: AgentPolicy, task: TaskDescriptor) -> RequirementDerivation:
    """Derive the task-specific requirement for ``policy`` and ``task``."""

    requirement: AssuranceRequirement = policy.base_requirement
    matched_rule_ids: list[str] = []
    for rule in sorted(policy.rules, key=lambda item: item.rule_id):
        if rule.condition.matches(task):
            matched_rule_ids.append(rule.rule_id)
            requirement = rule.contribution.apply_to(requirement)

    payload = RequirementDerivation.compute_hash_payload(
        agent_id=policy.agent_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_hash=policy.policy_hash(),
        task_hash=task.context_hash(),
        base_requirement=policy.base_requirement,
        matched_rule_ids=tuple(matched_rule_ids),
        final_requirement=requirement,
    )
    return RequirementDerivation(
        agent_id=policy.agent_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_hash=policy.policy_hash(),
        task_hash=task.context_hash(),
        base_requirement=policy.base_requirement,
        matched_rule_ids=tuple(matched_rule_ids),
        final_requirement=requirement,
        derivation_hash=derivation_hash(payload),
    )
