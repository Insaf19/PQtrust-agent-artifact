#!/usr/bin/env python3
"""Validate Stage 5 dual-signed trust contracts with generated lab keys."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pqtrust_agent.crypto.agent_evidence_manifest import (
    AgentEvidenceManifestError,
    ManifestFailure,
    load_agent_evidence_key_manifest,
    resolve_local_agent_evidence_key,
)
from pqtrust_agent.crypto.contract_signer import OpenSSLContractSigner
from pqtrust_agent.evidence.decimal_json import dumps_decimal_json
from pqtrust_agent.models.catalog import load_profile_catalog
from pqtrust_agent.models.common import EvidenceAlgorithm
from pqtrust_agent.models.preference import load_agent_cost_preference
from pqtrust_agent.models.protocol import NegotiationProposal, NegotiationReveal
from pqtrust_agent.models.selection import SELECTOR_IMPLEMENTATION_VERSION
from pqtrust_agent.negotiation.cost_evidence import load_selector_cost_evidence
from pqtrust_agent.negotiation.selector import run_bilateral_selector
from pqtrust_agent.policy.compiler import compile_local_policy
from pqtrust_agent.policy.loader import load_agent_manifest, load_agent_policy, load_scenario
from pqtrust_agent.protocol.commitment import CommitRevealSession, create_commitment
from pqtrust_agent.protocol.contract_builder import build_signed_contract, build_unsigned_contract
from pqtrust_agent.protocol.errors import ProtocolTimeError
from pqtrust_agent.protocol.replay import InMemoryReplayRegistry
from pqtrust_agent.protocol.signature import algorithm_for_contract_evidence
from pqtrust_agent.protocol.transcript import build_transcript
from pqtrust_agent.protocol.verification import verify_signed_contract

SCENARIOS = (
    "low-risk-public-tool",
    "sensitive-enterprise-api",
    "critical-edge-command",
    "low-risk-quantum-ready-tool",
)


def _agent_file(agent_id: str) -> str:
    return f"{agent_id.replace('-', '_')}.yaml"


def _fixture_hex(label: str) -> str:
    return hashlib.sha256(f"PQTrust laboratory fixture:{label}".encode()).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(dumps_decimal_json(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _catalog_expected_algorithms(catalog: Any) -> None:
    expected = {
        "P0": EvidenceAlgorithm.ML_DSA_65,
        "P1": EvidenceAlgorithm.ML_DSA_65,
        "P2": EvidenceAlgorithm.ML_DSA_65,
        "P3": EvidenceAlgorithm.ML_DSA_65,
        "P4": EvidenceAlgorithm.ML_DSA_87,
    }
    for profile_id, algorithm in expected.items():
        observed = algorithm_for_contract_evidence(
            catalog.get_profile(profile_id).contract_evidence_mode
        )
        if observed != algorithm:
            raise ValueError(
                f"profile {profile_id} contract evidence requires {observed.value}, "
                f"expected {algorithm.value}"
            )


def _failure_dict(
    failure: ManifestFailure,
    *,
    scenario_id: str | None = None,
    phase: str | None = None,
) -> dict[str, str | None]:
    payload = failure.to_dict()
    if scenario_id is not None:
        payload["scenario_id"] = scenario_id
    if phase is not None:
        payload["phase"] = phase
    return payload


def _exception_failure(
    *,
    scenario_id: str,
    phase: str,
    exc: Exception,
    reference_time: datetime | None = None,
) -> dict[str, Any]:
    if isinstance(exc, ProtocolTimeError):
        payload = exc.to_dict()
        payload["scenario_id"] = scenario_id
        payload["debug"] = repr(exc)
        return payload
    return {
        "scenario_id": scenario_id,
        "phase": phase,
        "agent_id": None,
        "requested_algorithm": None,
        "error_code": type(exc).__name__,
        "message": str(exc),
        "debug": repr(exc),
        "supplied_reference_time": (
            reference_time.isoformat().replace("+00:00", "Z")
            if reference_time is not None
            else None
        ),
    }


def _deterministic_activation_time(*, issued_at: datetime, expires_at: datetime) -> datetime:
    lifetime = expires_at - issued_at
    offset = min(timedelta(seconds=1), lifetime / 2)
    activation_time = issued_at + offset
    if not issued_at <= activation_time < expires_at:
        raise ValueError("deterministic activation time outside contract lease")
    return activation_time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/protocol"))
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("configs/profiles/trust_profiles.yaml"),
    )
    parser.add_argument("--agents-dir", type=Path, default=Path("configs/agents"))
    parser.add_argument("--policies-dir", type=Path, default=Path("configs/policies"))
    parser.add_argument("--preferences-dir", type=Path, default=Path("configs/preferences"))
    parser.add_argument("--scenarios-dir", type=Path, default=Path("configs/scenarios"))
    parser.add_argument(
        "--cost-evidence-dir",
        type=Path,
        default=Path("artifacts/paired-cost-calibration/r2-vs-confirmatory"),
    )
    parser.add_argument(
        "--key-manifest",
        type=Path,
        default=Path("artifacts/protocol/agent_evidence_key_manifest.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    key_manifest_path = (
        (repo / args.key_manifest).resolve()
        if not args.key_manifest.is_absolute()
        else args.key_manifest
    )
    if not key_manifest_path.exists():
        raise SystemExit(
            "run scripts/generate_agent_evidence_keys.sh before signed-contract validation"
        )
    catalog = load_profile_catalog(args.catalog)
    _catalog_expected_algorithms(catalog)
    catalog_hash = catalog.catalog_hash()
    cost_evidence = load_selector_cost_evidence(args.cost_evidence_dir, catalog)
    errors: list[dict[str, str | None]] = []
    try:
        key_manifest = load_agent_evidence_key_manifest(key_manifest_path, repo_root=repo)
    except AgentEvidenceManifestError as exc:
        errors.extend(_failure_dict(failure) for failure in exc.failures)
        key_manifest = None
    try:
        signer = OpenSSLContractSigner()
    except Exception as exc:
        errors.append(
            {
                "scenario_id": None,
                "phase": "openssl_backend",
                "agent_id": None,
                "requested_algorithm": None,
                "error_code": "OPENSSL_BACKEND_INVALID",
                "message": str(exc),
                "debug": repr(exc),
            }
        )
        signer = None
    registry = InMemoryReplayRegistry()
    contracts: list[dict[str, Any]] = []
    adversarial: list[dict[str, Any]] = []
    if key_manifest is None or signer is None:
        summary = {
            "artifact": "signed_contract_validation",
            "scenario_count": 0,
            "contracts": contracts,
            "validation_errors": errors,
            "validation_passed": False,
        }
        _write_json(args.output_dir / "signed_contract_validation.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 1
    expected_keys = key_manifest.expected_keys()
    for scenario_id in SCENARIOS:
        try:
            scenario = load_scenario(args.scenarios_dir / f"{scenario_id.replace('-', '_')}.yaml")
            evaluation_time = scenario.evaluation_time_utc
            init_manifest = load_agent_manifest(
                args.agents_dir / _agent_file(scenario.initiator_agent_id)
            )
            resp_manifest = load_agent_manifest(
                args.agents_dir / _agent_file(scenario.responder_agent_id)
            )
            init_comp = compile_local_policy(
                catalog,
                init_manifest,
                load_agent_policy(args.policies_dir / _agent_file(scenario.initiator_agent_id)),
                scenario.task,
                evaluation_time,
            )
            resp_comp = compile_local_policy(
                catalog,
                resp_manifest,
                load_agent_policy(args.policies_dir / _agent_file(scenario.responder_agent_id)),
                scenario.task,
                evaluation_time,
            )
            init_pref = load_agent_cost_preference(
                args.preferences_dir / _agent_file(scenario.initiator_agent_id)
            )
            resp_pref = load_agent_cost_preference(
                args.preferences_dir / _agent_file(scenario.responder_agent_id)
            )
            selection = run_bilateral_selector(
                scenario=scenario,
                catalog_profile_ids=catalog.profile_ids(),
                catalog_hash=catalog_hash,
                initiator_compilation=init_comp,
                responder_compilation=resp_comp,
                initiator_preference=init_pref,
                responder_preference=resp_pref,
                cost_evidence=cost_evidence,
            )
            session_id = _fixture_hex(f"{scenario_id}:session")
            init_reveal = NegotiationReveal(
                proposal=NegotiationProposal(
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
                ),
                nonce_hex=_fixture_hex(f"{scenario_id}:initiator:nonce"),
            )
            resp_reveal = NegotiationReveal(
                proposal=init_reveal.proposal.model_copy(
                    update={
                        "agent_id": scenario.responder_agent_id,
                        "agent_role": "responder",
                        "manifest_hash": resp_manifest.manifest_hash(),
                        "policy_compilation_hash": resp_comp.compilation_hash,
                        "preference_hash": resp_pref.preference_hash(),
                        "local_safe_profile_ids": resp_comp.safe_profile_ids,
                    }
                ),
                nonce_hex=_fixture_hex(f"{scenario_id}:responder:nonce"),
            )
            session = CommitRevealSession(
                session_id=session_id,
                activation_time=evaluation_time,
                replay_registry=registry,
            )
            session.register_commitment("initiator", create_commitment(init_reveal))
            session.register_commitment("responder", create_commitment(resp_reveal))
            session.accept_reveal(init_reveal, verification_time=evaluation_time)
            session.accept_reveal(resp_reveal, verification_time=evaluation_time)
            transcript = build_transcript(
                initiator_reveal=init_reveal,
                responder_reveal=resp_reveal,
                selection_result=selection,
                catalog_profile_ids=catalog.profile_ids(),
                created_at=evaluation_time,
            )
            unsigned = build_unsigned_contract(
                transcript=transcript,
                selection_result=selection,
                catalog=catalog,
                issued_at=evaluation_time,
            )
            activation_time = _deterministic_activation_time(
                issued_at=unsigned.issued_at,
                expires_at=unsigned.expires_at,
            )
            profile = catalog.get_profile(selection.selected_profile_id)
            algorithm = algorithm_for_contract_evidence(profile.contract_evidence_mode)
            signed = build_signed_contract(
                unsigned_contract=unsigned,
                initiator_signature=signer.sign_contract(
                    unsigned,
                    resolve_local_agent_evidence_key(
                        key_manifest,
                        agent_id=scenario.initiator_agent_id,
                        role="initiator",
                        algorithm=algorithm,
                        signer=signer,
                    ),
                ),
                responder_signature=signer.sign_contract(
                    unsigned,
                    resolve_local_agent_evidence_key(
                        key_manifest,
                        agent_id=scenario.responder_agent_id,
                        role="responder",
                        algorithm=algorithm,
                        signer=signer,
                    ),
                ),
            )
            verify_signed_contract(
                signed,
                transcript=transcript,
                selection_result=selection,
                catalog=catalog,
                expected_keys=expected_keys,
                verification_time=activation_time,
                signer=signer,
                replay_registry=registry,
            )
            _write_json(
                args.output_dir / "contracts" / f"{scenario_id}.json",
                signed.model_dump(mode="json"),
            )
            contracts.append(
                {
                    "scenario_id": scenario_id,
                    "contract_id": unsigned.contract_id,
                    "signed_contract_hash": signed.signed_contract_hash,
                    "selected_profile_id": unsigned.selected_profile_id,
                    "algorithm": algorithm.value,
                    "issued_at": unsigned.issued_at.isoformat().replace("+00:00", "Z"),
                    "expires_at": unsigned.expires_at.isoformat().replace("+00:00", "Z"),
                    "deterministic_activation_time": activation_time.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "activation_within_lease": unsigned.issued_at
                    <= activation_time
                    < unsigned.expires_at,
                    "replay_registration_passed": True,
                    "both_signatures_valid": True,
                    "contract_verification_passed": True,
                    "validation_passed": True,
                }
            )
            tampered = signed.model_copy(
                update={
                    "unsigned_contract": unsigned.model_copy(update={"tls_group": "tampered"})
                }
            )
            try:
                verify_signed_contract(
                    tampered,
                    transcript=transcript,
                    selection_result=selection,
                    catalog=catalog,
                    expected_keys=expected_keys,
                    verification_time=activation_time,
                    signer=signer,
                )
                adversarial.append({"case": f"{scenario_id}:modified_tls_group", "rejected": False})
            except Exception:
                adversarial.append({"case": f"{scenario_id}:modified_tls_group", "rejected": True})
            boundary_checks = (
                (
                    "before_issued_at",
                    unsigned.issued_at - timedelta(seconds=1),
                    False,
                ),
                ("issued_at_plus_1s", unsigned.issued_at + timedelta(seconds=1), True),
                ("at_expires_at", unsigned.expires_at, False),
                ("after_expires_at", unsigned.expires_at + timedelta(seconds=1), False),
            )
            for check_name, reference_time, should_pass in boundary_checks:
                try:
                    verify_signed_contract(
                        signed,
                        transcript=transcript,
                        selection_result=selection,
                        catalog=catalog,
                        expected_keys=expected_keys,
                        verification_time=reference_time,
                        signer=signer,
                        replay_registry=InMemoryReplayRegistry(),
                    )
                    passed = True
                    error_code = None
                except ProtocolTimeError as exc:
                    passed = False
                    error_code = exc.code
                adversarial.append(
                    {
                        "case": f"{scenario_id}:expiry:{check_name}",
                        "reference_time": reference_time.isoformat().replace("+00:00", "Z"),
                        "expected_pass": should_pass,
                        "passed": passed,
                        "expectation_met": passed is should_pass,
                        "error_code": error_code,
                    }
                )
        except AgentEvidenceManifestError as exc:
            errors.extend(
                _failure_dict(failure, scenario_id=scenario_id, phase=failure.phase)
                for failure in exc.failures
            )
        except Exception as exc:
            errors.append(_exception_failure(scenario_id=scenario_id, phase="scenario", exc=exc))
    summary = {
        "artifact": "signed_contract_validation",
        "time_source": "deterministic_laboratory_fixture",
        "scenario_count": len(contracts),
        "contracts": contracts,
        "validation_errors": errors,
        "validation_passed": not errors and len(contracts) == len(SCENARIOS),
    }
    adversarial_payload = {
        "artifact": "adversarial_validation",
        "cases": adversarial,
        "validation_passed": all(
            item.get("expectation_met", item.get("rejected")) for item in adversarial
        ),
    }
    _write_json(args.output_dir / "signed_contract_validation.json", summary)
    _write_json(args.output_dir / "adversarial_validation.json", adversarial_payload)
    _write_checksums(args.output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["validation_passed"] and adversarial_payload["validation_passed"] else 1


def _write_checksums(output_dir: Path) -> None:
    files = sorted(
        path
        for path in output_dir.rglob("*.json")
        if path.is_file() and not path.name.startswith(".")
    )
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(output_dir)}"
        for path in files
    ]
    checksum_path = output_dir / "checksums.sha256"
    tmp = checksum_path.with_name(".checksums.sha256.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, checksum_path)


if __name__ == "__main__":
    raise SystemExit(main())
