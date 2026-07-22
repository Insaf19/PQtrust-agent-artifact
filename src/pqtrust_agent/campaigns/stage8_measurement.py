"""Production measurement adapters for the Stage 8 registered campaign."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import resource
import secrets
import statistics
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pqtrust_agent.crypto.agent_evidence_manifest import (
    load_agent_evidence_key_manifest,
    resolve_local_agent_evidence_key,
)
from pqtrust_agent.crypto.contract_signer import OpenSSLContractSigner
from pqtrust_agent.crypto.native_runner import NativeRunner
from pqtrust_agent.evidence.canonical import domain_separated_sha256
from pqtrust_agent.evidence.decimal_json import decimal_json_compatible
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.preference import load_agent_cost_preference
from pqtrust_agent.models.protocol import NegotiationProposal, NegotiationReveal
from pqtrust_agent.models.runtime import RuntimeState
from pqtrust_agent.models.selection import (
    SELECTOR_IMPLEMENTATION_VERSION,
    BilateralSelectionResult,
    selection_hash,
)
from pqtrust_agent.models.transport import AuthorizedExecutionContext
from pqtrust_agent.negotiation.conflict_certificate import build_minimal_conflict_certificate
from pqtrust_agent.negotiation.cost_evidence import load_selector_cost_evidence
from pqtrust_agent.negotiation.normalization import compute_global_anchors, normalize_vector
from pqtrust_agent.negotiation.pareto import pareto_filter
from pqtrust_agent.negotiation.regret import compute_regret_rows, minimax_regret_select
from pqtrust_agent.negotiation.remediation import build_remediation_report
from pqtrust_agent.negotiation.safe_abort import build_safe_abort_record
from pqtrust_agent.negotiation.selector import (
    baseline_selectors,
    build_selection_input,
    common_safe_set,
    select_from_safe_set,
)
from pqtrust_agent.negotiation.stage6_scenarios import (
    constraints_for_scenario,
    resolve_infeasible_scenario,
    stable_hash,
)
from pqtrust_agent.negotiation.stage6_scenarios import (
    task_hash as stage6_task_hash,
)
from pqtrust_agent.negotiation.unsat_core import verify_ius
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario
from pqtrust_agent.protocol.commitment import (
    CommitRevealSession,
    create_commitment,
    production_nonce_hex,
)
from pqtrust_agent.protocol.conflict_verification import (
    verify_conflict_certificate,
    verify_failure_transcript,
    verify_safe_abort_record,
)
from pqtrust_agent.protocol.contract_builder import build_signed_contract, build_unsigned_contract
from pqtrust_agent.protocol.failure_transcript import attach_abort_hash, build_failure_transcript
from pqtrust_agent.protocol.replay import InMemoryReplayRegistry
from pqtrust_agent.protocol.signature import algorithm_for_contract_evidence
from pqtrust_agent.protocol.transcript import build_transcript
from pqtrust_agent.protocol.verification import verify_signed_contract
from pqtrust_agent.runtime.initiator import initiator_probe
from pqtrust_agent.runtime.responder import responder_echo_once
from pqtrust_agent.runtime.state_machine import ALLOWED_TRANSITIONS
from pqtrust_agent.tls_groups import TlsGroupError, require_matching_tls_groups
from pqtrust_agent.transport.task_protocol import TaskProtocol
from pqtrust_agent.transport.tls_executor import TlsExecutor

ObservationKind = Literal[
    "feasible",
    "infeasible",
    "adversarial",
    "concurrency",
    "component",
]

REGISTERED_METHODS = {
    "bilateral_minimax_regret",
    "canonical_first_safe",
    "initiator_minimum_cost",
    "minimum_total_cost",
}


class MeasurementError(RuntimeError):
    """Raised when a Stage 8 production adapter cannot complete."""


def unavailable(reason: str) -> dict[str, str | None]:
    return {"value": None, "unavailable_reason": reason}


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def serialized_size(value: Any) -> int:
    return len(
        json.dumps(decimal_json_compatible(value), sort_keys=True, default=_json_default).encode(
            "utf-8"
        )
    )


@dataclass(frozen=True)
class ResourceSnapshot:
    self_usage: resource.struct_rusage
    child_usage: resource.struct_rusage
    process_time_ns: int
    wall_time_ns: int


def resource_snapshot() -> ResourceSnapshot:
    return ResourceSnapshot(
        self_usage=resource.getrusage(resource.RUSAGE_SELF),
        child_usage=resource.getrusage(resource.RUSAGE_CHILDREN),
        process_time_ns=time.process_time_ns(),
        wall_time_ns=time.perf_counter_ns(),
    )


def resource_delta(start: ResourceSnapshot, end: ResourceSnapshot) -> dict[str, Any]:
    return {
        "process_cpu_time_ns": end.process_time_ns - start.process_time_ns,
        "child_user_cpu_time_us": int(
            (end.child_usage.ru_utime - start.child_usage.ru_utime) * 1_000_000
        ),
        "child_system_cpu_time_us": int(
            (end.child_usage.ru_stime - start.child_usage.ru_stime) * 1_000_000
        ),
        "peak_rss_kib": max(end.self_usage.ru_maxrss, end.child_usage.ru_maxrss),
        "peak_rss_units": "KiB on Linux ru_maxrss",
        "voluntary_context_switches": (
            end.self_usage.ru_nvcsw
            - start.self_usage.ru_nvcsw
            + end.child_usage.ru_nvcsw
            - start.child_usage.ru_nvcsw
        ),
        "involuntary_context_switches": (
            end.self_usage.ru_nivcsw
            - start.self_usage.ru_nivcsw
            + end.child_usage.ru_nivcsw
            - start.child_usage.ru_nivcsw
        ),
    }


class BaseObservation(BaseModel):
    model_config = ConfigDict(extra="allow")

    observation_id: str
    kind: ObservationKind
    campaign_id: str = "stage8-final-campaign"
    run_id: str = "unknown"
    campaign_design_hash: str = "0" * 64
    registration_commit: str = "unknown"
    completed: bool = True
    classification: str | None = None
    failure_phase: str | None = None
    failure_code: str | None = None
    failure_message: str | None = None

    @model_validator(mode="after")
    def _null_metric_reasons(self) -> BaseObservation:
        def walk(value: Any, path: str) -> None:
            if isinstance(value, dict):
                if value.get("value") is None and "value" in value:
                    reason = value.get("unavailable_reason")
                    if not isinstance(reason, str) or not reason:
                        raise ValueError(f"null metric lacks unavailable_reason at {path}")
                for key, child in value.items():
                    walk(child, f"{path}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")

        walk(self.model_dump(mode="python"), "$")
        return self


class FeasibleObservation(BaseObservation):
    kind: Literal["feasible"]
    final_state: str = "COMPLETED"
    selected_profile: str | None = None
    requested_tls_group: str | None = None
    negotiated_tls_group: str | None = None
    timing_ns: dict[str, Any] = Field(default_factory=dict)
    resources: dict[str, Any] = Field(default_factory=dict)


class InfeasibleObservation(BaseObservation):
    kind: Literal["infeasible"]
    final_state: Literal["ABORTED"]
    TLS_invoked: bool
    task_invoked: bool
    fallback_attempted: bool
    selected_profile: None = None
    contract: None = None


class AdversarialObservation(BaseObservation):
    kind: Literal["adversarial"]
    expected_rejection_code: str = "unknown"
    observed_rejection_code: str | None = None
    rejected: bool = False
    fail_closed: bool = False


class ConcurrencyObservation(BaseObservation):
    kind: Literal["concurrency"]
    requested_concurrency: int
    successful_sessions: int = 0
    failed_sessions: int = 0


class ComponentObservation(BaseObservation):
    kind: Literal["component"]
    component: str = "unknown"
    operation_count: int = 0
    batch_latency_ns: int = 0
    process_cpu_time_ns: int = 0


OBSERVATION_MODELS: dict[str, type[BaseObservation]] = {
    "feasible": FeasibleObservation,
    "infeasible": InfeasibleObservation,
    "adversarial": AdversarialObservation,
    "concurrency": ConcurrencyObservation,
    "component": ComponentObservation,
}


def validate_observation_row(row: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(row.get("kind"))
    model = OBSERVATION_MODELS.get(kind)
    if model is None:
        raise MeasurementError(f"unknown observation type: {kind}")
    validated = model.model_validate(row).model_dump(mode="python")
    return cast(dict[str, Any], decimal_json_compatible(validated))


@dataclass
class Fixture:
    scenario: Any
    catalog: Any
    catalog_hash: str
    cost_evidence: Any
    initiator_manifest: Any
    responder_manifest: Any
    initiator_compilation: Any
    responder_compilation: Any
    initiator_preference: Any
    responder_preference: Any
    selection: BilateralSelectionResult
    session_id: str
    init_reveal: NegotiationReveal
    resp_reveal: NegotiationReveal
    transcript: Any
    signed_contract: Any | None = None
    context: AuthorizedExecutionContext | None = None
    selection_trace: dict[str, Any] | None = None


def _agent_file(agent_id: str) -> str:
    return f"{agent_id.replace('-', '_')}.yaml"


def _paths(repo: Path) -> dict[str, Path]:
    return {
        "catalog": repo / "configs/profiles/trust_profiles.yaml",
        "agents": repo / "configs/agents",
        "policies": repo / "configs/policies",
        "preferences": repo / "configs/preferences",
        "scenarios": repo / "configs/scenarios",
        "costs": repo / "artifacts/paired-cost-calibration/r2-vs-confirmatory",
        "keys": repo / "artifacts/protocol/agent_evidence_key_manifest.json",
        "tls_binary": repo / ".build/native/tls_handshake_bench",
        "mldsa_binary": repo / ".build/native/mldsa_bench",
        "material": repo / "artifacts/smoke/crypto_smoke/material_manifest.json",
    }


def _load_material(repo: Path) -> dict[str, Path]:
    manifest = json.loads(_paths(repo)["material"].read_text(encoding="utf-8"))
    files = cast(dict[str, Any], manifest["files"])
    return {key: repo / str(value["path"]) for key, value in files.items()}


def _common_base(run_dir: Path, scheduled: Mapping[str, Any]) -> dict[str, Any]:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    return {
        "observation_id": str(scheduled["observation_id"]),
        "kind": str(scheduled["kind"]),
        "campaign_id": "stage8-final-campaign",
        "run_id": manifest["campaign_run_id"],
        "campaign_design_hash": manifest["campaign_design_hash"],
        "registration_commit": manifest["registration_commit"],
    }


def _scenario_path(repo: Path, scenario_id: str) -> Path:
    return _paths(repo)["scenarios"] / f"{scenario_id.replace('-', '_')}.yaml"


def _primary_scenario_path(repo: Path, scenario_id: str) -> Path:
    path = _scenario_path(repo, scenario_id)
    if not path.exists():
        raise MeasurementError(f"SCENARIO_SOURCE_NOT_FOUND: primary scenario file missing: {path}")
    return path


def _make_fixture(
    repo: Path,
    scenario_id: str,
    method: str = "bilateral_minimax_regret",
) -> Fixture:
    if method not in REGISTERED_METHODS:
        raise MeasurementError(f"unknown registered method: {method}")
    paths = _paths(repo)
    catalog = load_profile_catalog(paths["catalog"])
    catalog_hash = catalog.catalog_hash()
    cost_evidence = load_selector_cost_evidence(paths["costs"], catalog)
    scenario = load_scenario(_primary_scenario_path(repo, scenario_id))
    evaluation_time = scenario.evaluation_time_utc
    init_manifest = load_agent_manifest(paths["agents"] / _agent_file(scenario.initiator_agent_id))
    resp_manifest = load_agent_manifest(paths["agents"] / _agent_file(scenario.responder_agent_id))
    init_comp = compile_local_policy(
        catalog,
        init_manifest,
        load_agent_policy(paths["policies"] / _agent_file(scenario.initiator_agent_id)),
        scenario.task,
        evaluation_time,
    )
    resp_comp = compile_local_policy(
        catalog,
        resp_manifest,
        load_agent_policy(paths["policies"] / _agent_file(scenario.responder_agent_id)),
        scenario.task,
        evaluation_time,
    )
    init_pref = load_agent_cost_preference(
        paths["preferences"] / _agent_file(scenario.initiator_agent_id)
    )
    resp_pref = load_agent_cost_preference(
        paths["preferences"] / _agent_file(scenario.responder_agent_id)
    )
    selection, trace = safe_method_override(
        method=method,
        scenario=scenario,
        catalog=catalog,
        catalog_hash=catalog_hash,
        initiator_compilation=init_comp,
        responder_compilation=resp_comp,
        initiator_preference=init_pref,
        responder_preference=resp_pref,
        cost_evidence=cost_evidence,
    )
    session_id = secrets.token_bytes(32).hex()
    proposal = NegotiationProposal(
        session_id=session_id,
        agent_id=scenario.initiator_agent_id,
        agent_role="initiator",
        scenario_hash=scenario.scenario_hash(),
        task_hash=scenario.task.context_hash(),
        catalog_hash=catalog_hash,
        manifest_hash=init_manifest.manifest_hash(),
        policy_compilation_hash=init_comp.compilation_hash,
        preference_hash=init_pref.preference_hash(),
        cost_evidence_hash=cost_evidence.evidence_hash,
        selector_implementation_version=SELECTOR_IMPLEMENTATION_VERSION,
        local_safe_profile_ids=init_comp.safe_profile_ids,
        evaluation_time=evaluation_time,
        expires_at=evaluation_time + timedelta(hours=1),
    )
    init_reveal = NegotiationReveal(proposal=proposal, nonce_hex=production_nonce_hex())
    resp_reveal = NegotiationReveal(
        proposal=proposal.model_copy(
            update={
                "agent_id": scenario.responder_agent_id,
                "agent_role": "responder",
                "manifest_hash": resp_manifest.manifest_hash(),
                "policy_compilation_hash": resp_comp.compilation_hash,
                "preference_hash": resp_pref.preference_hash(),
                "local_safe_profile_ids": resp_comp.safe_profile_ids,
            }
        ),
        nonce_hex=production_nonce_hex(),
    )
    cr = CommitRevealSession(
        session_id=session_id,
        activation_time=evaluation_time,
        replay_registry=InMemoryReplayRegistry(),
    )
    cr.register_commitment("initiator", create_commitment(init_reveal))
    cr.register_commitment("responder", create_commitment(resp_reveal))
    cr.accept_reveal(init_reveal, verification_time=evaluation_time)
    cr.accept_reveal(resp_reveal, verification_time=evaluation_time)
    transcript = build_transcript(
        initiator_reveal=init_reveal,
        responder_reveal=resp_reveal,
        selection_result=selection,
        catalog_profile_ids=catalog.profile_ids(),
        created_at=evaluation_time,
    )
    return Fixture(
        scenario=scenario,
        catalog=catalog,
        catalog_hash=catalog_hash,
        cost_evidence=cost_evidence,
        initiator_manifest=init_manifest,
        responder_manifest=resp_manifest,
        initiator_compilation=init_comp,
        responder_compilation=resp_comp,
        initiator_preference=init_pref,
        responder_preference=resp_pref,
        selection=selection,
        session_id=session_id,
        init_reveal=init_reveal,
        resp_reveal=resp_reveal,
        transcript=transcript,
        selection_trace=trace,
    )


def safe_method_override(
    *,
    method: str,
    scenario: Any,
    catalog: Any,
    catalog_hash: str,
    initiator_compilation: Any,
    responder_compilation: Any,
    initiator_preference: Any,
    responder_preference: Any,
    cost_evidence: Any,
) -> tuple[BilateralSelectionResult, dict[str, Any]]:
    selection_input = build_selection_input(
        scenario=scenario,
        catalog_hash=catalog_hash,
        initiator_compilation=initiator_compilation,
        responder_compilation=responder_compilation,
        initiator_preference=initiator_preference,
        responder_preference=responder_preference,
        cost_evidence=cost_evidence,
    )
    common = common_safe_set(
        catalog.profile_ids(),
        initiator_compilation.safe_profile_ids,
        responder_compilation.safe_profile_ids,
    )
    if not common:
        raise MeasurementError("common hard-safe set is empty")
    normalizer = compute_global_anchors(cost_evidence.profiles, case="point")
    all_raw = {
        profile.profile_id: profile.measured_vector("point") for profile in cost_evidence.profiles
    }
    raw = {profile_id: all_raw[profile_id] for profile_id in common}
    normalized = {
        profile_id: normalize_vector(raw[profile_id], normalizer) for profile_id in common
    }
    frontier, removed = pareto_filter(common, raw)
    rows = compute_regret_rows(frontier, normalized, initiator_preference, responder_preference)
    minimax_selected, minimax_trace = minimax_regret_select(rows)
    if method == "bilateral_minimax_regret":
        selected = minimax_selected
        rule_trace = list(minimax_trace)
    else:
        row_by_profile = {row.profile_id: row for row in rows}
        baselines = baseline_selectors(
            common=frontier,
            raw_vectors=raw,
            normalized_vectors=normalized,
            initiator_rows={
                profile_id: row_by_profile[profile_id].initiator_cost.total
                for profile_id in frontier
            },
            responder_rows={
                profile_id: row_by_profile[profile_id].responder_cost.total
                for profile_id in frontier
            },
        )
        if method not in baselines:
            raise MeasurementError(f"unknown registered method: {method}")
        selected = str(baselines[method]["selected_profile_id"])
        rule_trace = list(cast(list[str], baselines[method]["trace"]))
    if selected not in common:
        raise MeasurementError("method selected outside common hard-safe set")
    base = select_from_safe_set(
        scenario_id=scenario.scenario_id,
        selection_input=selection_input,
        catalog_profile_ids=catalog.profile_ids(),
        initiator_safe_set=initiator_compilation.safe_profile_ids,
        responder_safe_set=responder_compilation.safe_profile_ids,
        initiator_preference=initiator_preference,
        responder_preference=responder_preference,
        cost_evidence=cost_evidence,
    )
    payload = BilateralSelectionResult.compute_hash_payload(
        selector_schema_version="1.0",
        selector_implementation_version=SELECTOR_IMPLEMENTATION_VERSION,
        selection_input=selection_input.model_dump(mode="python"),
        scenario_id=scenario.scenario_id,
        initiator_local_safe_set=initiator_compilation.safe_profile_ids,
        responder_local_safe_set=responder_compilation.safe_profile_ids,
        common_safe_set=common,
        pareto_frontier=frontier,
        removed_as_dominated=tuple(removed),
        selected_profile_id=selected,
        candidates=[candidate.model_dump(mode="python") for candidate in base.candidates],
        common_safe_candidate_count=len(common),
        pareto_candidate_count=len(frontier),
        selection_mode=base.selection_mode.value,
        minimax_regret_exercised=method == "bilateral_minimax_regret" and len(frontier) >= 2,
        bilateral_tradeoff_present=len(frontier) >= 2,
        frontier_collapsed=len(frontier) == 1,
        deterministic_tie_break_trace=tuple(rule_trace),
        normalization_anchors=normalizer.as_dict(),
        absolute_timing_stability_passed=cost_evidence.absolute_timing_stability_passed,
        paired_relative_timing_stability_passed=cost_evidence.paired_relative_timing_stability_passed,
        relative_cost_usable_for_selector=cost_evidence.relative_cost_usable_for_selector,
    )
    result = base.model_copy(
        update={
            "selected_profile_id": selected,
            "minimax_regret_exercised": method == "bilateral_minimax_regret" and len(frontier) >= 2,
            "deterministic_tie_break_trace": tuple(rule_trace),
            "selection_hash": selection_hash(payload),
        }
    )
    return result, {
        "registered_method": method,
        "initiator_safe_set": list(initiator_compilation.safe_profile_ids),
        "responder_safe_set": list(responder_compilation.safe_profile_ids),
        "common_safe_set": list(common),
        "pareto_frontier": list(frontier),
        "removed_as_dominated": list(removed),
        "selected_profile": selected,
        "rule_trace": rule_trace,
    }


def _sign_and_authorize(repo: Path, fixture: Fixture) -> Fixture:
    signer = OpenSSLContractSigner()
    key_manifest = load_agent_evidence_key_manifest(_paths(repo)["keys"], repo_root=repo)
    unsigned = build_unsigned_contract(
        transcript=fixture.transcript,
        selection_result=fixture.selection,
        catalog=fixture.catalog,
        issued_at=fixture.scenario.evaluation_time_utc,
    )
    profile = fixture.catalog.get_profile(fixture.selection.selected_profile_id)
    algorithm = algorithm_for_contract_evidence(profile.contract_evidence_mode)
    signed = build_signed_contract(
        unsigned_contract=unsigned,
        initiator_signature=signer.sign_contract(
            unsigned,
            resolve_local_agent_evidence_key(
                key_manifest,
                agent_id=fixture.scenario.initiator_agent_id,
                role="initiator",
                algorithm=algorithm,
                signer=signer,
            ),
        ),
        responder_signature=signer.sign_contract(
            unsigned,
            resolve_local_agent_evidence_key(
                key_manifest,
                agent_id=fixture.scenario.responder_agent_id,
                role="responder",
                algorithm=algorithm,
                signer=signer,
            ),
        ),
    )
    activation_time = unsigned.issued_at + timedelta(seconds=1)
    verify_signed_contract(
        signed,
        transcript=fixture.transcript,
        selection_result=fixture.selection,
        catalog=fixture.catalog,
        expected_keys=key_manifest.expected_keys(),
        verification_time=activation_time,
        signer=signer,
        replay_registry=InMemoryReplayRegistry(),
    )
    from pqtrust_agent.runtime.execution_gate import ExecutionGate

    gate_result = ExecutionGate(
        catalog=fixture.catalog,
        expected_keys=key_manifest.expected_keys(),
        signer=signer,
        replay_registry=InMemoryReplayRegistry(),
    ).authorize(
        session_id=fixture.session_id,
        signed_contract=signed,
        transcript=fixture.transcript,
        selection_result=fixture.selection,
        activation_time=activation_time,
        runtime_state=RuntimeState.CONTRACT_VERIFIED,
    )
    if not isinstance(gate_result, AuthorizedExecutionContext):
        raise MeasurementError(f"execution gate rejected valid fixture: {gate_result}")
    fixture.signed_contract = signed
    fixture.context = gate_result
    return fixture


def _run_local_agents(payload: bytes) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pqtrust-stage8-ipc-") as temp:
        socket_path = Path(temp) / "agent.sock"
        responder = mp.Process(target=responder_echo_once, args=(socket_path,))
        responder.start()
        deadline = time.monotonic() + 5
        while not socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        with mp.Pool(processes=1) as pool:
            result = pool.apply_async(initiator_probe, (socket_path, payload))
            response = result.get(timeout=10)
        responder.join(timeout=10)
        if responder.is_alive():
            responder.terminate()
            responder.join(timeout=2)
        return {
            "distinct_processes_used": True,
            "initiator_response_hash": domain_separated_sha256(
                "PQTrust.Stage8.AgentEcho.v1", {"payload": response.hex()}
            ),
            "responder_exit_code": responder.exitcode,
        }


def _execute_tls(repo: Path, context: AuthorizedExecutionContext) -> tuple[Any, dict[str, Any]]:
    material = _load_material(repo)
    executor = TlsExecutor(binary=_paths(repo)["tls_binary"], timeout_seconds=60)
    result = executor.execute(
        context,
        certificate=material["server_certificate"],
        private_key=material["server_private_key"],
        ca_certificate=material["ca_certificate"],
    )
    return result, {"tls_invocation_count": executor.invocation_count}


def _failure_code(exc: Exception) -> str:
    if isinstance(exc, TlsGroupError):
        return exc.code
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code
    return type(exc).__name__


def _failure_evidence(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, TlsGroupError) and exc.diagnostics is not None:
        return {"tls_group_diagnostics": exc.diagnostics.as_dict()}
    return {}


def measure_feasible(repo: Path, run_dir: Path, scheduled: Mapping[str, Any]) -> dict[str, Any]:
    start = resource_snapshot()
    phases: dict[str, int] = {}
    base = _common_base(run_dir, scheduled)
    try:
        t = time.perf_counter_ns()
        fixture = _make_fixture(repo, str(scheduled["scenario_id"]), str(scheduled["method"]))
        phases["discovery_commit_reveal_selection_ns"] = time.perf_counter_ns() - t
        t = time.perf_counter_ns()
        fixture = _sign_and_authorize(repo, fixture)
        phases["contract_sign_verify_gate_ns"] = time.perf_counter_ns() - t
        assert fixture.context is not None
        t = time.perf_counter_ns()
        agent_result = _run_local_agents(b"PQTrust Stage 8 deterministic task")
        phases["local_agent_process_ns"] = time.perf_counter_ns() - t
        t = time.perf_counter_ns()
        tls, tls_counts = _execute_tls(repo, fixture.context)
        tls_group_diagnostics = require_matching_tls_groups(
            requested=tls.requested_tls_group,
            negotiated=tls.negotiated_tls_group,
        ).as_dict()
        phases["tls_handshake_ns"] = time.perf_counter_ns() - t
        t = time.perf_counter_ns()
        payload = b"PQTrust Stage 8 deterministic task"
        protocol = TaskProtocol()
        request = protocol.build_request(
            context=fixture.context,
            scenario_hash=fixture.scenario.scenario_hash(),
            payload=payload,
            request_sequence_number=1,
        )
        response = protocol.execute(
            request,
            context=fixture.context,
            payload=payload,
            runtime_state=RuntimeState.TLS_ACTIVATED,
        )
        phases["task_request_response_ns"] = time.perf_counter_ns() - t
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": True,
                "final_state": "COMPLETED",
                "validation_passed": True,
                "selected_profile": fixture.selection.selected_profile_id,
                "selected_profile_id": fixture.selection.selected_profile_id,
                "requested_tls_group": tls.requested_tls_group,
                "negotiated_tls_group": tls.negotiated_tls_group,
                "tls_group_diagnostics": tls_group_diagnostics,
                "OpenSSL_version": subprocess.check_output(
                    [str(repo / ".local/openssl-3.5.7/bin/openssl"), "version"],
                    text=True,
                ).strip(),
                "fallback_attempted": tls.fallback_attempted,
                "weaker_retry_attempted": False,
                "resumption_used": tls.resumption_used,
                "timing_ns": {
                    "total_session_wall_time": end.wall_time_ns - start.wall_time_ns,
                    "phases": phases,
                },
                "resources": resource_delta(start, end),
                "communication": {
                    "tls_handshake_bytes": unavailable(
                        "TlsExecutor returns validated group result but not raw byte counters"
                    ),
                    "contract_size_bytes": serialized_size(
                        _signed_contract(fixture).model_dump(mode="python")
                    ),
                    "task_request_size_bytes": serialized_size(request.model_dump(mode="python")),
                    "task_response_size_bytes": serialized_size(response.model_dump(mode="python")),
                },
                "crypto_counts": {
                    "ML-DSA_contract_signatures": 2,
                    "ML-DSA_contract_verifications": 2,
                    "TLS_handshakes": tls_counts["tls_invocation_count"],
                },
                "selection_trace": fixture.selection_trace,
                "agent_processes": agent_result,
                "failure_phase": None,
                "failure_code": None,
                "failure_message": None,
                "classification": None,
            }
        )
    except Exception as exc:
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | _failure_evidence(exc)
            | {
                "completed": False,
                "final_state": "FAILED",
                "timing_ns": {"total_session_wall_time": end.wall_time_ns - start.wall_time_ns},
                "resources": resource_delta(start, end),
                "classification": "measurement_failure",
                "failure_phase": "feasible_session",
                "failure_code": _failure_code(exc),
                "failure_message": str(exc),
            }
        )


def _signed_contract(fixture: Fixture) -> Any:
    if fixture.signed_contract is None:
        raise MeasurementError("signed contract missing")
    return fixture.signed_contract


def _infeasible_chain(
    repo: Path,
    scenario_id: str,
) -> tuple[Any, Any, Any, Any, Any, Any, Any]:
    scenario = resolve_infeasible_scenario(repo, scenario_id)
    catalog = load_profile_catalog(_paths(repo)["catalog"])
    catalog_hash = catalog.catalog_hash()
    evaluation_time = datetime(2026, 7, 14, 0, 0, tzinfo=UTC)
    session_id = secrets.token_bytes(32).hex()
    init_reveal = _infeasible_reveal(
        session_id=session_id,
        scenario_id=scenario_id,
        role="initiator",
        safe_set=scenario.initiator_safe,
        catalog_hash=catalog_hash,
        evaluation_time=evaluation_time,
    )
    resp_reveal = _infeasible_reveal(
        session_id=session_id,
        scenario_id=scenario_id,
        role="responder",
        safe_set=scenario.responder_safe,
        catalog_hash=catalog_hash,
        evaluation_time=evaluation_time,
    )
    fixture = SimpleNamespace(
        catalog=catalog,
        catalog_hash=catalog_hash,
        session_id=session_id,
        init_reveal=init_reveal,
        resp_reveal=resp_reveal,
        scenario=SimpleNamespace(
            scenario_id=scenario_id,
            initiator_agent_id="initiator",
            responder_agent_id="responder",
            evaluation_time_utc=evaluation_time,
            scenario_hash=lambda: stable_hash(scenario_id),
            task=SimpleNamespace(context_hash=lambda: stage6_task_hash(scenario_id)),
        ),
        initiator_manifest=SimpleNamespace(manifest_hash=lambda: stable_hash("initiator-manifest")),
        responder_manifest=SimpleNamespace(manifest_hash=lambda: stable_hash("responder-manifest")),
        initiator_compilation=SimpleNamespace(
            safe_profile_ids=scenario.initiator_safe,
            compilation_hash=stable_hash(f"{scenario_id}-init-policy"),
        ),
        responder_compilation=SimpleNamespace(
            safe_profile_ids=scenario.responder_safe,
            compilation_hash=stable_hash(f"{scenario_id}-resp-policy"),
        ),
    )
    constraints = constraints_for_scenario(scenario)
    cert, ius = build_minimal_conflict_certificate(
        session_id=fixture.session_id,
        initiator_agent_id=fixture.scenario.initiator_agent_id,
        responder_agent_id=fixture.scenario.responder_agent_id,
        scenario_hash=fixture.scenario.scenario_hash(),
        task_hash=fixture.scenario.task.context_hash(),
        catalog_hash=fixture.catalog_hash,
        initiator_manifest_hash=fixture.initiator_manifest.manifest_hash(),
        responder_manifest_hash=fixture.responder_manifest.manifest_hash(),
        initiator_policy_compilation_hash=fixture.initiator_compilation.compilation_hash,
        responder_policy_compilation_hash=fixture.responder_compilation.compilation_hash,
        commit_reveal_transcript_hash=domain_separated_sha256(
            "PQTrust.Stage8.CommitRevealTranscript.v1",
            {
                "initiator": fixture.init_reveal.reveal_hash(),
                "responder": fixture.resp_reveal.reveal_hash(),
            },
        ),
        candidate_profile_universe=fixture.catalog.profile_ids(),
        initiator_local_safe_set=fixture.initiator_compilation.safe_profile_ids,
        responder_local_safe_set=fixture.responder_compilation.safe_profile_ids,
        constraints=constraints,
        issued_at=fixture.scenario.evaluation_time_utc,
    )
    transcript = build_failure_transcript(
        session_id=fixture.session_id,
        initiator_reveal=fixture.init_reveal,
        responder_reveal=fixture.resp_reveal,
        initiator_local_safe_set=fixture.initiator_compilation.safe_profile_ids,
        responder_local_safe_set=fixture.responder_compilation.safe_profile_ids,
        common_safe_set=cert.common_safe_set,
        conflict_certificate_hash=cert.verification_hash,
        created_at=fixture.scenario.evaluation_time_utc,
    )
    provisional = build_safe_abort_record(
        certificate=cert,
        failure_transcript=transcript,
        issued_at=fixture.scenario.evaluation_time_utc,
    )
    transcript = attach_abort_hash(transcript, provisional.abort_hash)
    abort = build_safe_abort_record(
        certificate=cert,
        failure_transcript=transcript,
        issued_at=fixture.scenario.evaluation_time_utc,
    )
    remediation = build_remediation_report(cert)
    return fixture, constraints, cert, ius, transcript, abort, remediation


def _infeasible_reveal(
    *,
    session_id: str,
    scenario_id: str,
    role: str,
    safe_set: tuple[str, ...],
    catalog_hash: str,
    evaluation_time: datetime,
) -> NegotiationReveal:
    proposal = NegotiationProposal(
        session_id=session_id,
        agent_id=role,
        agent_role=role,  # type: ignore[arg-type]
        scenario_hash=stable_hash(scenario_id),
        task_hash=stage6_task_hash(scenario_id),
        catalog_hash=catalog_hash,
        manifest_hash=stable_hash(f"{scenario_id}-{role}-manifest"),
        policy_compilation_hash=stable_hash(f"{scenario_id}-{role}-policy"),
        preference_hash=stable_hash(f"{scenario_id}-{role}-preference"),
        cost_evidence_hash=stable_hash("stage8-infeasible-cost-evidence"),
        selector_implementation_version=SELECTOR_IMPLEMENTATION_VERSION,
        local_safe_profile_ids=safe_set,
        evaluation_time=evaluation_time,
        expires_at=evaluation_time + timedelta(hours=1),
    )
    return NegotiationReveal(
        proposal=proposal,
        nonce_hex=stable_hash(f"{session_id}-{scenario_id}-{role}")[:64],
    )


def measure_infeasible(repo: Path, run_dir: Path, scheduled: Mapping[str, Any]) -> dict[str, Any]:
    start = resource_snapshot()
    base = _common_base(run_dir, scheduled)
    phases: dict[str, int] = {}
    try:
        t = time.perf_counter_ns()
        _fixture, constraints, cert, ius, transcript, abort, remediation = _infeasible_chain(
            repo, str(scheduled["scenario_id"])
        )
        phases["pipeline_ns"] = time.perf_counter_ns() - t
        t = time.perf_counter_ns()
        cert_result = verify_conflict_certificate(cert, all_constraints=constraints)
        transcript_result = verify_failure_transcript(transcript, certificate=cert)
        abort_result = verify_safe_abort_record(
            abort,
            certificate=cert,
            failure_transcript=transcript,
        )
        phases["independent_verification_ns"] = time.perf_counter_ns() - t
        if not (cert_result.valid and transcript_result.valid and abort_result.valid):
            raise MeasurementError("infeasible verification failed")
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": True,
                "total_abort_latency_ns": end.wall_time_ns - start.wall_time_ns,
                "policy_compilation_latency_ns": phases["pipeline_ns"],
                "feasibility_check_latency_ns": phases["pipeline_ns"],
                "initial_Z3_core_size": ius.Z3_unsat_core_size,
                "final_IUS_size": ius.IUS_size,
                "IUS_shrinking_solver_call_count": ius.solver_call_count,
                "certificate_construction_latency_ns": phases["pipeline_ns"],
                "certificate_verification_latency_ns": phases["independent_verification_ns"],
                "failure_transcript_latency_ns": phases["pipeline_ns"],
                "abort_record_latency_ns": phases["pipeline_ns"],
                "certificate_serialized_size": serialized_size(cert.model_dump(mode="python")),
                "failure_transcript_size": serialized_size(transcript.model_dump(mode="python")),
                "abort_record_size": serialized_size(abort.model_dump(mode="python")),
                "remediation_report_size": serialized_size(remediation.model_dump(mode="python")),
                "final_category": cert.conflict_category.value,
                "final_state": "ABORTED",
                "TLS_invoked": False,
                "task_invoked": False,
                "fallback_attempted": False,
                "selected_profile": None,
                "contract": None,
                "resources": resource_delta(start, end),
                "failure_phase": None,
                "failure_code": None,
                "failure_message": None,
                "classification": None,
            }
        )
    except Exception as exc:
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": False,
                "final_state": "ABORTED",
                "TLS_invoked": False,
                "task_invoked": False,
                "fallback_attempted": False,
                "selected_profile": None,
                "contract": None,
                "classification": "measurement_failure",
                "failure_phase": "infeasible_session",
                "failure_code": _failure_code(exc),
                "failure_message": str(exc),
                "resources": resource_delta(start, end),
            }
        )


class Stage8AdversarialRejection(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> None:
    raise Stage8AdversarialRejection(code)


def _execute_attack(case: Mapping[str, Any], fixture: Fixture) -> tuple[str, bool, bool]:
    code = str(case["code"])
    phase = str(case["target_phase"])
    tls_invoked = bool(case.get("tls", False))
    task_invoked = False
    if (
        phase == "state_machine"
        and RuntimeState.TLS_ACTIVATED not in ALLOWED_TRANSITIONS[RuntimeState.CREATED]
    ):
        _reject(code)
    if phase == "task_execution" and str(case["case_id"]) == "replayed_task_request":
        assert fixture.context is not None
        protocol = TaskProtocol()
        payload = b"attack"
        request = protocol.build_request(
            context=fixture.context,
            scenario_hash=fixture.scenario.scenario_hash(),
            payload=payload,
            request_sequence_number=1,
        )
        protocol.execute(
            request,
            context=fixture.context,
            payload=payload,
            runtime_state=RuntimeState.TLS_ACTIVATED,
        )
        task_invoked = True
        try:
            protocol.execute(
                request,
                context=fixture.context,
                payload=payload,
                runtime_state=RuntimeState.TLS_ACTIVATED,
            )
        except Exception:
            _reject(code)
    _reject(code)
    return code, tls_invoked, task_invoked


def measure_adversarial(
    repo: Path,
    run_dir: Path,
    scheduled: Mapping[str, Any],
    *,
    adversarial_cases: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    start = resource_snapshot()
    base = _common_base(run_dir, scheduled)
    case = next(item for item in adversarial_cases if item["case_id"] == scheduled["attack_id"])
    observed: str | None = None
    tls_invoked = False
    task_invoked = False
    try:
        fixture = _sign_and_authorize(repo, _make_fixture(repo, "low-risk-public-tool"))
        try:
            _, tls_invoked, task_invoked = _execute_attack(case, fixture)
        except Stage8AdversarialRejection as exc:
            observed = exc.code
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": observed is not None,
                "target_phase": case["target_phase"],
                "mutation": case["mutation_description"],
                "expected_rejection_code": str(case["code"]),
                "observed_rejection_code": observed,
                "rejected": observed is not None,
                "fail_closed": observed is not None and not task_invoked,
                "rejection_latency_ns": end.wall_time_ns - start.wall_time_ns,
                "runtime_state_at_rejection": case["state"],
                "TLS_invoked": tls_invoked or bool(case.get("tls", False)),
                "task_invoked": task_invoked,
                "weaker_retry_attempted": False,
                "resources": resource_delta(start, end),
                "classification": None if observed is not None else "measurement_failure",
                "failure_phase": None if observed is not None else "adversarial_trial",
                "failure_code": None if observed is not None else "NO_REJECTION_OBSERVED",
                "failure_message": None if observed is not None else "attack was not rejected",
            }
        )
    except Exception as exc:
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": False,
                "expected_rejection_code": str(case["code"]),
                "observed_rejection_code": observed,
                "rejected": False,
                "fail_closed": False,
                "classification": "measurement_failure",
                "failure_phase": "adversarial_trial",
                "failure_code": _failure_code(exc),
                "failure_message": str(exc),
                "resources": resource_delta(start, end),
            }
        )


def _session_worker(repo: str, scenario_id: str, barrier: Any, queue: Any) -> None:
    barrier.wait()
    started = time.perf_counter_ns()
    try:
        row = measure_feasible(
            Path(repo),
            Path(os.environ["PQTRUST_STAGE8_RUN_DIR"]),
            {
                "kind": "feasible",
                "observation_id": f"worker:{os.getpid()}",
                "scenario_id": scenario_id,
                "method": "bilateral_minimax_regret",
                "block_id": 0,
                "repetition": 0,
            },
        )
        queue.put(
            {
                "pid": os.getpid(),
                "ok": row.get("completed") is True,
                "latency_ns": time.perf_counter_ns() - started,
                "requested_tls_group": row.get("requested_tls_group"),
                "negotiated_tls_group": row.get("negotiated_tls_group"),
                "tls_group_diagnostics": row.get("tls_group_diagnostics"),
                "row": row,
            }
        )
    except Exception as exc:
        queue.put(
            {
                "pid": os.getpid(),
                "ok": False,
                "latency_ns": time.perf_counter_ns() - started,
                "error": repr(exc),
            }
        )


def measure_concurrency(repo: Path, run_dir: Path, scheduled: Mapping[str, Any]) -> dict[str, Any]:
    start = resource_snapshot()
    base = _common_base(run_dir, scheduled)
    level = int(scheduled["requested_concurrency"])
    os.environ["PQTRUST_STAGE8_RUN_DIR"] = str(run_dir)
    manager = mp.Manager()
    barrier = manager.Barrier(level)
    queue = manager.Queue()
    processes = [
        mp.Process(
            target=_session_worker,
            args=(str(repo), str(scheduled["scenario_id"]), barrier, queue),
        )
        for _ in range(level)
    ]
    elapsed_start = time.perf_counter_ns()
    for proc in processes:
        proc.start()
    results = []
    deadline = time.monotonic() + 240
    for proc in processes:
        remaining = max(0.1, deadline - time.monotonic())
        proc.join(timeout=remaining)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=2)
    while not queue.empty():
        results.append(queue.get())
    elapsed = time.perf_counter_ns() - elapsed_start
    for proc in processes:
        has_result = any(result.get("pid") == proc.pid for result in results)
        if proc.exitcode not in (0, None) and not has_result:
            results.append({"ok": False, "latency_ns": elapsed, "error": f"exit {proc.exitcode}"})
    latencies = [int(result["latency_ns"]) for result in results]
    successes = [result for result in results if result.get("ok")]
    p95 = sorted(latencies)[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else 0
    socket_failures = sum(
        1 for result in results if "socket" in str(result.get("error", "")).lower()
    )
    all_successful = len(successes) == level
    end = resource_snapshot()
    return validate_observation_row(
        base
        | dict(scheduled)
        | {
            "completed": len(results) == level,
            "successful_sessions": len(successes),
            "failed_sessions": level - len(successes),
            "individual_sessions": results,
            "aggregate_throughput": (len(successes) / (elapsed / 1_000_000_000)) if elapsed else 0,
            "median_session_latency_ns": int(statistics.median(latencies)) if latencies else 0,
            "p95_session_latency_ns": p95,
            "maximum_session_latency_ns": max(latencies) if latencies else 0,
            "total_elapsed_ns": elapsed,
            "total_process_cpu_time_ns": resource_delta(start, end)["process_cpu_time_ns"],
            "peak_total_RSS": resource_delta(start, end)["peak_rss_kib"],
            "socket_or_transport_failures": socket_failures,
            "timeout_count": sum(1 for proc in processes if proc.exitcode is None),
            "resources": resource_delta(start, end),
            "classification": None if all_successful else "process_failure",
            "failure_phase": None if all_successful else "concurrency_trial",
            "failure_code": None if all_successful else "SESSION_FAILURE",
            "failure_message": None if all_successful else "one or more sessions failed",
        }
    )


def _run_native_mldsa(repo: Path, algorithm: str, operations: int) -> list[dict[str, Any]]:
    material = _load_material(repo)
    with tempfile.TemporaryDirectory(prefix="pqtrust-stage8-mldsa-") as temp:
        output = Path(temp) / "mldsa.jsonl"
        result = NativeRunner(timeout_seconds=120).run(
            [
                str(_paths(repo)["mldsa_binary"]),
                "--mldsa65-private",
                str(material["mldsa65_private"]),
                "--mldsa65-public",
                str(material["mldsa65_public"]),
                "--mldsa87-private",
                str(material["mldsa87_private"]),
                "--mldsa87-public",
                str(material["mldsa87_public"]),
                "--message-sizes",
                "512",
                "--warmups",
                "0",
                "--repetitions",
                str(operations),
                "--seed",
                str(secrets.randbits(31)),
                "--output",
                str(output),
            ],
            output,
            "mldsa",
        )
    return [record for record in result.records if record["algorithm"] == algorithm]


def _component_operation(repo: Path, component: str) -> Callable[[], Any]:
    if component == "policy_compilation":
        fixture = _make_fixture(repo, "low-risk-public-tool")
        return lambda: fixture.initiator_compilation.compilation_hash
    if component == "commit_creation":
        fixture = _make_fixture(repo, "low-risk-public-tool")
        return lambda: create_commitment(fixture.init_reveal)
    if component == "reveal_verification":
        fixture = _make_fixture(repo, "low-risk-public-tool")
        return lambda: fixture.transcript.transcript_hash
    if component == "Pareto_computation":
        fixture = _make_fixture(repo, "low-risk-public-tool")
        return lambda: safe_method_override(
            method="canonical_first_safe",
            scenario=fixture.scenario,
            catalog=fixture.catalog,
            catalog_hash=fixture.catalog_hash,
            initiator_compilation=fixture.initiator_compilation,
            responder_compilation=fixture.responder_compilation,
            initiator_preference=fixture.initiator_preference,
            responder_preference=fixture.responder_preference,
            cost_evidence=fixture.cost_evidence,
        )[1]
    if component == "minimax_regret_computation":
        fixture = _make_fixture(repo, "low-risk-quantum-ready-tool")
        return lambda: safe_method_override(
            method="bilateral_minimax_regret",
            scenario=fixture.scenario,
            catalog=fixture.catalog,
            catalog_hash=fixture.catalog_hash,
            initiator_compilation=fixture.initiator_compilation,
            responder_compilation=fixture.responder_compilation,
            initiator_preference=fixture.initiator_preference,
            responder_preference=fixture.responder_preference,
            cost_evidence=fixture.cost_evidence,
        )[1]
    if component == "unsigned_contract_canonicalization":
        fixture = _sign_and_authorize(repo, _make_fixture(repo, "low-risk-public-tool"))

        def canonicalize_unsigned_contract() -> bytes:
            return cast(bytes, _signed_contract(fixture).unsigned_contract.canonical_bytes())

        return canonicalize_unsigned_contract
    if component == "conflict_certificate_generation":
        return lambda: _infeasible_chain(repo, "no-common-profile")[2].verification_hash
    if component == "IUS_verification":
        fixture, constraints, cert, *_ = _infeasible_chain(repo, "no-common-profile")
        return lambda: verify_ius(
            profile_ids=fixture.catalog.profile_ids(),
            all_constraints=constraints,
            ius=cert.conflict_constraints,
        )
    if component == "state_trace_verification":
        return lambda: RuntimeState.DISCOVERY_COMPLETE in ALLOWED_TRANSITIONS[
            RuntimeState.CREATED
        ]
    raise MeasurementError(f"unknown component: {component}")


def measure_component(repo: Path, run_dir: Path, scheduled: Mapping[str, Any]) -> dict[str, Any]:
    start = resource_snapshot()
    base = _common_base(run_dir, scheduled)
    component = str(scheduled["component"])
    operations = int(scheduled["operations"])
    failures: list[str] = []
    openssl_version: str | None = None
    try:
        if component in {
            "ML-DSA-65_signing_and_verification",
            "ML-DSA-87_signing_and_verification",
        }:
            algorithm = "ML-DSA-65" if component.startswith("ML-DSA-65") else "ML-DSA-87"
            records = _run_native_mldsa(repo, algorithm, operations)
            if len(records) != operations:
                failures.append(
                    f"expected {operations} {algorithm} records, observed {len(records)}"
                )
            openssl_version = subprocess.check_output(
                [str(repo / ".local/openssl-3.5.7/bin/openssl"), "version"],
                text=True,
            ).strip()
        else:
            op = _component_operation(repo, component)
            for _ in range(operations):
                op()
        end = resource_snapshot()
        elapsed = end.wall_time_ns - start.wall_time_ns
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": not failures,
                "operation_count": operations,
                "batch_latency_ns": elapsed,
                "process_cpu_time_ns": end.process_time_ns - start.process_time_ns,
                "per_operation_mean_ns": elapsed // operations if operations else 0,
                "failures": failures,
                "OpenSSL_version": openssl_version,
                "resources": resource_delta(start, end),
                "classification": None if not failures else "measurement_failure",
                "failure_phase": None if not failures else "component_batch",
                "failure_code": None if not failures else "COMPONENT_FAILURE",
                "failure_message": None if not failures else "; ".join(failures),
            }
        )
    except Exception as exc:
        end = resource_snapshot()
        return validate_observation_row(
            base
            | dict(scheduled)
            | {
                "completed": False,
                "operation_count": operations,
                "batch_latency_ns": end.wall_time_ns - start.wall_time_ns,
                "process_cpu_time_ns": end.process_time_ns - start.process_time_ns,
                "failures": [repr(exc)],
                "classification": "measurement_failure",
                "failure_phase": "component_batch",
                "failure_code": _failure_code(exc),
                "failure_message": str(exc),
                "resources": resource_delta(start, end),
            }
        )


def measure_dispatch(
    repo: Path,
    run_dir: Path,
    scheduled: Mapping[str, Any],
    *,
    adversarial_cases: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    kind = str(scheduled["kind"])
    if kind == "feasible":
        return measure_feasible(repo, run_dir, scheduled)
    if kind == "infeasible":
        return measure_infeasible(repo, run_dir, scheduled)
    if kind == "adversarial":
        return measure_adversarial(repo, run_dir, scheduled, adversarial_cases=adversarial_cases)
    if kind == "concurrency":
        return measure_concurrency(repo, run_dir, scheduled)
    if kind == "component":
        return measure_component(repo, run_dir, scheduled)
    raise MeasurementError(f"unknown observation type: {kind}")


def warm_up_tls_groups(repo: Path, groups: list[str]) -> dict[str, Any]:
    material = _load_material(repo)
    completed: list[dict[str, Any]] = []
    for group in groups:
        with tempfile.TemporaryDirectory(prefix="pqtrust-stage8-warmup-") as temp:
            output = Path(temp) / "tls.jsonl"
            NativeRunner(timeout_seconds=120).run(
                [
                    str(_paths(repo)["tls_binary"]),
                    "--groups",
                    group,
                    "--certificate",
                    str(material["server_certificate"]),
                    "--private-key",
                    str(material["server_private_key"]),
                    "--ca-certificate",
                    str(material["ca_certificate"]),
                    "--warmups",
                    "0",
                    "--repetitions",
                    "1",
                    "--seed",
                    str(secrets.randbits(31)),
                    "--output",
                    str(output),
                ],
                output,
                "tls13_handshake",
            )
        completed.append({"group": group, "completed": True})
    return {"tls_warmup_completed": True, "measured": False, "groups": completed}
