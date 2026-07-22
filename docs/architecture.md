# Architecture

## Stage 8 Campaign Layer

The Stage 8 campaign layer is implemented as a thin orchestration package under
`pqtrust_agent.campaigns`. It is intentionally separate from policy, selection,
protocol, and runtime algorithms so that final campaign registration cannot
change those algorithms after results are observed.

`register_stage8_campaign.py` freezes the design and schedule. The run and
resume entry points append raw JSONL observations to a single ignored run
directory and reject duplicate observation IDs. `validate_stage8.py` checks
sample counts, block balance, schedule adherence, safety invariants, checksums,
and provenance. `analyze_stage8_inventory.py` produces inventory summaries only;
publication statistics and figures are outside Stage 8.

The production measurement adapters live in
`pqtrust_agent.campaigns.stage8_measurement`. They are intentionally typed by
schedule observation kind rather than implemented as one generic record
builder. They reuse Stage 5-7 protocol, conflict, runtime, TLS, ML-DSA, task,
and state-machine modules and record raw integer nanosecond clocks plus
`getrusage` resource counters. Resume compares the run manifest to the current
registration commit, design hash, registration artifact hash, and schedule hash
before appending missing rows.

Stage 8 remains a single-machine local laboratory architecture. Local sockets,
local processes, and repository-native binaries are measured; wide-area network
latency and multi-host deployment behavior are outside this layer.

## Stage 9 Analysis Layer

The Stage 9 analysis layer is implemented under `pqtrust_agent.analysis`. It
reads immutable Stage 8 JSONL directly, verifies Stage 8 counts, checksums,
registered-design hash, registration commit, derived-summary counts, duplicate
IDs, and failure inventory, then writes derived analysis artifacts under
`artifacts/analysis/`.

The layer is deliberately outside the policy compiler, selector, protocol, and
runtime packages. It cannot change selection algorithms or campaign evidence.
Statistics, figure data packages, figure rendering, table generation, claim
ledger creation, and validation are exposed through separate scripts so that
the full bundle is generated only by explicit commands.

The architecture preserves provenance from every computed statistic back to raw
observation IDs. Figure packages contain the data and metadata needed to
reproduce plotted marks, and the claim ledger records allowed and prohibited
paper wording for descriptive, inferential, deterministic, validation, and
limitation claims.

This document records the permanent repository architecture for PQTrust-Agent.

At bootstrap, the repository defines package boundaries only. Protocol negotiation, policy compilation, cryptographic integration, attack implementations, metrics, and evidence pipelines will be added in later stages when their specifications and validation tests are introduced.

The source package uses a Python src-layout under `src/pqtrust_agent`.

## Stage 1 Trust Models

The first scientific implementation stage adds the permanent typed data model for public task descriptors, trust profiles, capability manifest payloads, resource envelopes, and assurance vectors. These models are deterministic Pydantic v2 objects with forbidden unknown fields and explicit validation rules.

Assurance is represented across separate dimensions:

- key-establishment assurance records whether the TLS group addresses classical and/or quantum key-establishment threats;
- endpoint-authentication assurance records what threat classes are addressed by TLS endpoint authentication;
- contract-evidence assurance records what threat classes are addressed by application-level ML-DSA evidence for manifests and future contracts.

The initial catalog deliberately represents classical TLS endpoint authentication explicitly. Hybrid or ML-KEM key establishment does not automatically imply fully post-quantum endpoint authentication, and the prototype does not claim that it does.

Assurance is a partial order rather than a scalar score. Threat-class dimensions use set inclusion, while fallback, resumption, and lease dimensions use named rank mappings. This avoids collapsing incomparable profiles into a fabricated aggregate security number.

Profiles P0-P4 are stored in `configs/profiles/trust_profiles.yaml`. Resource envelopes contain only null values at this stage because no calibration run has produced resource costs. Null means not yet constrained, not zero.

Canonicalization precedes hashing and future signing. Protocol payloads are converted to JSON-compatible values, encoded with RFC 8785 canonical JSON, and then hashed with domain-separated SHA-256. This makes hashes independent of dictionary insertion order and gives future signatures a stable byte representation.

## Stage 2 Policy Compiler

The second scientific stage adds deterministic task-requirement mapping and a
local Z3 policy compiler. The mapper applies monotone lower-bound task rules and
joins contributions, so rules can strengthen but not weaken assurance
requirements.

The compiler uses one finite-domain integer variable over the canonical profile
catalog indexes and encodes all active safety checks as labeled hard
constraints. It enumerates each satisfying local profile and independently
checks each candidate. Rejection explanations distinguish all violated
categories from a subset-minimal irreducible unsat core.

The stage intentionally does not implement cost normalization, regret vectors,
Pareto filtering, bilateral selection, commit-reveal, contract signing,
relaxation tokens, attack campaigns, TLS handshakes, keys, signatures, or
experimental measurements.

## Stage 3A Native Cryptographic Calibration

The third implementation stage adds a native calibration boundary under `native/` and Python orchestration under `src/pqtrust_agent/crypto/`. The native programs use OpenSSL 3.5.7 directly for TLS 1.3 handshakes and ML-DSA signing/verification.

TLS calibration uses paired memory BIOs to execute real client/server handshakes while excluding TCP and network-emulation effects. Later stages will add real TCP and `tc/netem` experiments. The TLS harness keeps endpoint authentication classical with one laboratory ECDSA P-256 certificate and varies only the TLS 1.3 key-establishment group from the P0-P4 catalog.

The stage still does not implement regret calculation, bilateral profile selection, commit-reveal, signed trust contracts, conflict certificates, A2A services, network emulation, final campaigns, plots, or paper result tables.

## Stage 4A/4B Bilateral Selector

Stage 4A adds a deterministic bilateral selector under
`src/pqtrust_agent/negotiation/`. It compiles each side's hard-safe local set,
intersects those sets, attaches checksum-verified paired TLS relative-cost
evidence, removes measured-cost-dominated profiles, and selects from the
Pareto-safe candidates by bilateral minimax regret.

The selector uses only measured TLS wall time, process CPU time, and handshake
bytes. Security and policy properties remain hard constraints from the policy
compiler. The stage does not add commit-reveal, signed manifests, signed trust
contracts, TLS channel binding, relaxation tokens, conflict certificates, A2A
services, attack campaigns, plots, or paper tables.

Stage 4B makes the selector reporting explicit about degeneracy. Selection
mode is derived from common-safe and Pareto-frontier sizes, complete
common-safe candidate audits explain every measured dominance removal, and
sensitivity classifications distinguish structural collapse from preference or
uncertainty robustness.

Stage 4B also adds one capability-ablation scenario,
`low-risk-quantum-ready-tool`, to exercise a non-degenerate measured frontier
using existing paired TLS evidence. The ablation is separate from the original
three primary scenarios and does not inject artificial costs. Its exhaustive
preference-conflict evaluation enumerates the deterministic 66 x 66 policy
weight grid and computes fairness gain against same-frontier safe baselines.

## Stage 5 Commit-Reveal And Contracts

Stage 5 adds immutable protocol and contract models, commit-reveal session
checks, transcript construction and verification, selected-profile-bound trust
contracts, local replay registries, and repository-local OpenSSL ML-DSA
contract signing support.

Transcript verification recomputes commitments, proposal hashes, common-safe
intersection, Pareto frontier, selected profile, selection hash, and transcript
hash. Signed contracts bind that transcript to selected-profile properties
copied from the validated catalog and to dual agent signatures over identical
unsigned contract bytes.

Endpoint TLS authentication remains classical in the current catalog. ML-DSA
signatures are application-level contract evidence only.
## Stage 6 Infeasible Negotiations

Stage 6 adds fail-closed handling for negotiations with no hard-safe bilateral
profile. A complete Z3 model is rebuilt over the catalog and tracked named
constraints. If genuine hard-constraint infeasibility is proved, the solver
core is sorted and shrunk by deterministic deletion to an IUS. The resulting
minimal conflict certificate is subset-minimal only; it is not a
minimum-cardinality claim.

Malformed inputs, tampering, invalid signatures, replay, and protocol integrity
failures are rejected as protocol failures rather than negotiation conflicts.
Safe abort records prohibit fallback, resumption, selected profiles, TLS
activation, and trust contracts.

The Stage 6 bundle is typed at the report boundary. Conflict-stage,
safe-abort, feasible-regression, adversarial, and bundle reports have distinct
frozen schemas with forbidden extra fields, so a safe-abort payload cannot be
serialized as a feasible or adversarial report. Bundle validation checks both
checksum integrity and semantic invariants.

The certificate chain is explicit: the certificate hash is embedded in the
failure transcript, the failure transcript hash is embedded in the abort
record, and all three artifacts must share the same session and scenario. The
bundle fails if any of the five infeasible scenarios lacks any link in this
chain or its remediation report.

Feasible regression reads the existing Stage 5 signed contracts and verifies
the selected profile and signed-contract hash remain unchanged while no
infeasible-session artifact is emitted. Adversarial validation is a mutation
matrix over certificates, failure transcripts, abort records, and
commit-reveal bindings; each mutation must be rejected fail-closed.
# Stage 7 Runtime Note

The repository now includes a local Stage 7 Web-of-Agents runtime layer in
`src/pqtrust_agent/runtime` and `src/pqtrust_agent/transport`. It connects the
existing commit-reveal, selector, signed-contract, conflict-certificate, and
safe-abort components to an explicit execution state machine and
contract-enforced TLS activation gate. The transport is laboratory-local only;
it does not implement Internet-wide discovery.

Stage 7 evidence generation and validation are centralized in
`src/pqtrust_agent/runtime/stage7_evidence.py`. The executable scripts are thin
`argparse` wrappers, so command help and imports cannot accidentally execute a
validation run. `scripts/validate_end_to_end_stage.py` is the only registered
orchestrator for replacing `artifacts/runtime/`; it writes into a temporary
sibling directory and atomically swaps the bundle after semantic validation and
checksum verification. `scripts/validate_stage7.py` is read-only and validates
an existing bundle.

The runtime artifact architecture separates deterministic scientific JSON from
sanitized process logs. Scientific JSON records session bindings, state-trace
hashes, process-log hashes, TLS group evidence, execution-gate outcomes,
adversarial rejection codes, and bundle reports. Process logs record only
sanitized process-role and transport events and exclude private keys, private
policy bodies, production nonces, and raw secret material.

Bundle validation recomputes deterministic hashes and inspects underlying
artifacts directly. Infeasible sessions fail validation if they report TLS
socket creation, native TLS invocation, task execution, fallback, or resumption.
Feasible sessions fail validation if process roles are not distinct, process
logs are missing or hash-mismatched, repository-local OpenSSL evidence is
absent, requested and negotiated TLS groups differ, or tasks execute before
authorization.
