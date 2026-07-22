# Stage 7 End-to-End Agent Runtime

Stage 7 adds a local Web-of-Agents execution path over the existing immutable
P0-P4 profiles, safe-set compilation, selector, commit-reveal transcript,
dual-signed contract, conflict certificate, and safe-abort evidence.

The runtime state machine is explicit and fail-closed. The feasible path is:

`CREATED -> DISCOVERY_COMPLETE -> COMMITMENTS_REGISTERED -> REVEALS_VERIFIED ->
FEASIBILITY_EVALUATED -> PROFILE_SELECTED -> CONTRACT_CREATED ->
CONTRACT_VERIFIED -> TLS_ACTIVATED -> TASK_EXECUTED -> COMPLETED`.

The infeasible path is:

`CREATED -> DISCOVERY_COMPLETE -> COMMITMENTS_REGISTERED -> REVEALS_VERIFIED ->
FEASIBILITY_EVALUATED -> CONFLICT_CERTIFIED -> ABORTED`.

All other transitions are rejected by `RuntimeStateMachine`.

Local discovery is laboratory-only. Agents advertise public metadata only:
agent ID, protocol version, manifest hash, message versions, endpoint
identifier, evidence-key fingerprint, and validity interval. Private policies
are not part of discovery. The accepted advertisements are bound into a
deterministic discovery hash.

Transport messages use length-prefixed canonical JSON frames. Each frame binds
the protocol version, message type, session ID, sequence number, payload length,
payload hash, and canonical payload. The decoder rejects oversized, truncated,
trailing-byte, duplicate-sequence, skipped-sequence, unknown-type, and
payload-hash mismatch cases.

The execution gate is the only path to TLS activation. It requires the runtime
to be in `CONTRACT_VERIFIED`, verifies the signed contract, checks both
signatures through the existing Stage 5 verifier, enforces the explicit
activation time, checks replay protection, verifies selected-profile membership
in both revealed safe sets, and binds transcript, selection, catalog properties,
and contract hash.

TLS execution is contract-bound. The requested OpenSSL TLS 1.3 group is copied
from the verified selected profile and must match the negotiated group. Fallback
and unauthorized resumption are rejected. Infeasible sessions never call the TLS
executor.

After TLS activation, the task protocol executes one deterministic laboratory
operation: SHA-256 over a fixed payload. Requests bind the session ID, contract
hash, scenario hash, payload hash, and request sequence number. Tasks before TLS
activation, wrong contract/session binding, modified payloads, and replays are
rejected.

Runtime evidence is written under `artifacts/runtime/` only by explicit Stage 7
commands. Process logs are separated from deterministic scientific JSON. The
Stage 7 scripts do not modify Stage 5 or Stage 6 artifacts and do not update the
paper or final performance figures.

The registered Stage 7 bundle is generated atomically by:

```sh
python scripts/validate_end_to_end_stage.py --replace-existing
```

The command stages the complete bundle in a temporary sibling directory,
generates deterministic session evidence, state traces, execution-gate and
adversarial reports, writes sanitized process logs, verifies semantic
invariants and checksums, and replaces `artifacts/runtime/` only after the
staged bundle passes. Without `--replace-existing`, existing runtime artifacts
are not overwritten.

`scripts/validate_stage7.py` is a read-only independent validator:

```sh
python scripts/validate_stage7.py --runtime-dir artifacts/runtime
```

All Stage 7 executable scripts use `argparse`; `--help` prints usage and exits
without validation or artifact writes, and importing a script performs no work.

Deterministic scientific JSON includes feasible and infeasible session
artifacts, per-scenario state traces under `artifacts/runtime/state_traces/`,
adversarial rejection evidence, execution-gate evidence, `stage7_validation.json`,
and `stage7_bundle_validation.json`. Sanitized process logs are stored
separately under `artifacts/runtime/process_logs/` because process IDs and
durations may be nondeterministic in real sessions. Session artifacts bind the
state-trace hash and process-log hashes, and the bundle validator recomputes
those hashes rather than trusting serialized pass booleans.

State traces record each transition with sequence index, previous state, event,
next state, deterministic laboratory timestamp, session ID, and transition
hash. Validation rejects illegal transitions, skipped mandatory states,
`TLS_ACTIVATED` before `CONTRACT_VERIFIED`, `TASK_EXECUTED` before
`TLS_ACTIVATED`, any state after `COMPLETED` or `ABORTED`, and infeasible
sessions that do not end in `ABORTED`.

Adversarial runtime evidence records the target phase and artifact, applied
mutation, expected and observed structured rejection code, fail-closed status,
runtime state at rejection, TLS invocation, task invocation, and weaker-retry
status. Cases rejected before TLS must not invoke TLS or task execution.
Handshake timeout and handshake failure cases may invoke TLS but must never
execute tasks or retry with a weaker group.

Commands:

```sh
python scripts/validate_end_to_end_stage.py --replace-existing
python scripts/validate_stage7.py --runtime-dir artifacts/runtime
```
