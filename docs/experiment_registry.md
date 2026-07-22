# Experiment Registry

This registry lists planned research questions, scenarios, baselines, attacks, and ablations. It intentionally contains no results.

## Research Questions

- RQ1 Safety: evaluate whether hard policy constraints prevent unsafe trust-contract decisions before optimization.
- RQ2 Decision quality: evaluate the quality of policy-compliant trust decisions under the planned scenarios.
- RQ3 Systems cost: evaluate computational, communication, and operational costs of the planned mechanisms.
- RQ4 Privacy and operability: evaluate privacy-preserving behavior and deployment operability.

## Planned Scenarios

- Cross-organization agent collaboration.
- Tool-mediated agent delegation.
- Multi-agent workflow with changing trust and capability requirements.

## Deterministic Stage-2 Scenario Definitions

- `low-risk-public-tool`
- `sensitive-enterprise-api`
- `critical-edge-command`

These scenarios are deterministic configuration fixtures used to validate local
safe-set compilation. Their common safe sets are sanity checks only and are not
bilateral selections or experimental results.

## Stage 3A Functional Smoke Gate

- Native TLS 1.3 handshake smoke over the five catalog TLS groups.
- Native ML-DSA-65 and ML-DSA-87 sign/verify smoke over 512-byte and 2048-byte calibration payloads.

These smoke runs are functional gates only. They validate that the repository-local OpenSSL build, laboratory material, native binaries, JSONL records, and checksum workflow are coherent before later statistical campaigns. They are not RQ results and must not be summarized as performance findings.

## Stage 3B Cryptographic Calibration

- Three-replicate TLS memory-BIO calibration for X25519, X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, and SecP384r1MLKEM1024.
- Three-replicate ML-DSA-65 and ML-DSA-87 sign/verify calibration for 512, 2048, and 8192 byte deterministic messages.
- Standard-library statistical summaries, hierarchical aggregation, deterministic hierarchical bootstrap intervals, and drift diagnostics.

Stage 3B is calibration evidence only. It is not a network experiment, attack campaign, bilateral trust-contract experiment, or paper-result generation stage.

## Stage 3C Calibration Quality and Confirmation

- Quality diagnostics for `calibration-20260713-r2` retain the raw campaign and
  distinguish integrity from timing stability.
- The confirmatory campaign repeats the same scientific design with new
  scheduling seeds and optional selected-CPU reuse from the baseline manifest.
- Cross-run comparison requires matching scientific design, catalog, OpenSSL
  version, native executable hashes, and case definitions.
- Exact configuration hashes may differ when only run identity and scheduling
  seeds differ; that difference is recorded but does not by itself reject a
  cross-run comparison.

Stage 3C does not implement negotiation, regret selection, attack campaigns, or
paper-result generation.

## Stage 3D Paired Relative Cost Calibration

- Paired block-normalized TLS cost analysis for
  `calibration-20260713-r2` versus `calibration-20260713-confirmatory`.
- Within-block P0-normalized ratios for P0-P4, all ordered TLS profile-pair
  comparisons, hierarchical paired aggregation, and paired bootstrap intervals.
- Separate ML-DSA-65 versus ML-DSA-87 paired summaries by message size.

Stage 3D preserves the failed absolute timing-stability finding and produces
calibrated evidence only. It does not implement bilateral negotiation, minimax
regret, policy weights, final scalar utilities, attacks, or paper results.

## Stage 4A Bilateral Selector Validation

- Three deterministic scenarios reuse the policy compiler safe sets.
- Registered basis-point preferences are loaded from `configs/preferences/`.
- The selector uses checksum-verified paired TLS relative-cost evidence from
  `artifacts/paired-cost-calibration/r2-vs-confirmatory/`.
- Primary selection uses measured-cost Pareto filtering and bilateral minimax
  regret with deterministic tie-breaking.
- Uncertainty and weight sensitivity are recorded as validation analyses.
- Safe-only deterministic baselines are recorded for later comparison.

Stage 4A still does not implement attacks, random baselines, unsafe baselines,
commit-reveal, signed trust contracts, A2A services, final statistical
evaluation, or paper-result generation.

## Stage 4B Non-Degenerate Selector Validation

- The original three scenarios remain primary scientific scenarios and are not
  changed.
- Their current measured frontiers legitimately collapse: one singleton
  common-safe set and two measured Pareto collapses.
- A separate `low-risk-quantum-ready-tool` capability ablation exercises a
  non-singleton measured frontier without artificial cost injection.
- The ablation uses the existing paired TLS evidence where `P1` is dominated
  and `P0`/`P3` are Pareto-incomparable because wall/CPU and byte costs trade
  off.
- Exhaustive deterministic preference-conflict evaluation covers the full
  66 x 66 basis-point grid and reports fairness gain relative to same-frontier
  safe baselines.

Stage 4B does not implement commit-reveal, contracts, signatures, A2A services,
attacks, random preferences, artificial measurements, production-frequency
claims for the ablation, or paper-result generation.

## Stage 5 Commit-Reveal And Signed Contracts

- Commit-reveal proposals bind session, scenario, task, catalog, manifest,
  policy-compilation, preference, cost-evidence, selector-version, local-safe
  set, and expiry fields before reveal.
- Transcripts bind both commitments, both reveals, recomputed common-safe
  intersection, Pareto frontier, selected profile, and selection hash.
- Unsigned contracts bind transcript and selection hashes to selected-profile
  properties copied from the validated catalog.
- Dual signatures use the ML-DSA parameter set required by the selected
  profile's contract-evidence mode.
- Contract evidence algorithms use canonical public names `ML-DSA-65` and
  `ML-DSA-87`; parser-boundary normalization is centralized and unknown values
  are rejected.
- The agent evidence-key manifest is public metadata only. Laboratory private
  keys are resolved from `.local/pqtrust-crypto/agents/` after validating the
  ten expected agent/algorithm entries, public fingerprints, private-key
  permissions, and private/public key pairs.
- P0/P1/P2/P3 require `ML-DSA-65`; P4 requires `ML-DSA-87`, as loaded from the
  profile catalog.
- Replay protection is local only, with in-memory test and atomic JSON-file
  laboratory implementations.
- Time-dependent protocol operations receive explicit timezone-aware UTC
  reference times. Production adapters pass production UTC time explicitly;
  deterministic laboratory validation passes fixture activation times inside
  the historical contract interval.
- Contract activation uses inclusive `issued_at` and exclusive `expires_at`
  semantics. Before-issue, at-expiry, after-expiry, timezone-naive, and invalid
  interval cases fail closed with stable time error codes.

Stage 5 does not implement network services, attacks, tc/netem, final
campaigns, figures, paper text, or post-quantum TLS endpoint authentication.

## Planned Baselines

- No policy-compiled trust contract baseline.
- Classical transport-only security baseline.
- Static allow-list policy baseline.
- Optimization-first decision baseline without hard pre-filtering.

## Planned Adversarial Attacks

- Policy bypass attempts.
- Capability misrepresentation.
- Downgrade attempts against negotiated security posture.
- Replay or stale-evidence attempts.
- Trust-state manipulation attempts.

## Planned Ablations

- Remove hard policy pre-filtering.
- Remove assurance evidence checks.
- Remove post-quantum readiness constraints.
- Vary trust-threshold configuration.
- Vary evidence freshness requirements.

## Stage 8 Final Registered Campaigns

Stage 8 freezes `configs/campaigns/stage8_final_campaign.yaml` before
execution. The design fixes sample sizes, block structure, deterministic method
ordering seed, timeout and failure policies, measured metrics, exclusion rules,
and the prohibition on adaptive stopping or post-hoc method changes.

The feasible primary campaign compares only safe selection rules:
`bilateral_minimax_regret`, `canonical_first_safe`,
`initiator_minimum_cost`, and `minimum_total_cost`. Hard constraints are applied
before every method, and no baseline may select an unsafe profile.

Infeasible, adversarial, concurrency, and component-overhead campaigns are
registered in the same schedule. Raw evidence is append-only JSONL; derived
inventory artifacts contain no fabricated rows and reference raw observation
IDs rather than final figures.

The registered design is not modified by execution. The Stage 8 runner now
dispatches by typed observation kind to real production adapters. Feasible
method overrides are controlled: both local hard-safe sets are compiled,
intersected, Pareto-processed where required, and the registered safe rule is
applied; any selection outside the common safe set is rejected. Static unsafe
or unshielded baselines are not registered.

`RUN_COMPLETE` requires the exact registered counts: 480 feasible, 150
infeasible, 200 adversarial, 100 concurrency, and 110 component batches. It also
requires schedule exhaustion, duplicate-free IDs, schema validation, safety
invariants, and checksum verification.
## Stage 6 Conflict Experiments

Registered infeasible scenarios:

- `no-common-profile`
- `assurance-floor-conflict`
- `TLS-group-capability-conflict`
- `lease-policy-conflict`
- `multi-cause-conflict`

The scenarios exercise conflict taxonomy, deterministic Z3 core shrinking to an
IUS, failure transcript binding, safe abort invariants, and adversarial
rejection. Remediation reports are non-binding and never applied automatically.

For each registered infeasible scenario the expected artifact chain is one
certificate, one failure transcript, one safe-abort record, and one remediation
report. `no-common-profile` proves empty bilateral profile support.
`assurance-floor-conflict` shares supported profiles before policy and becomes
infeasible only after the task assurance floor is applied. `lease-policy-conflict`
keeps all non-lease requirements otherwise compatible and becomes infeasible
only because the task minimum lease exceeds the agent/profile lease ceiling.
The final categories are derived from the verified IUS, not assigned by
scenario name.

Feasible regression covers exactly:

- `low-risk-public-tool`
- `sensitive-enterprise-api`
- `critical-edge-command`
- `low-risk-quantum-ready-tool`

For each feasible scenario the report compares the Stage 5 selected profile and
signed-contract hash before and after Stage 6 and records that no certificate,
failure transcript, or abort record was produced.

The adversarial matrix has fifteen registered attacks: removed conflict
constraint, added unrelated constraint, modified source hash, false
empty-common-safe-set claim, false IUS minimality claim, satisfiable set
presented as unsatisfiable, modified conflict category, modified certificate
hash, modified failure transcript, selected profile attached after abort, trust
contract attached after abort, fallback attempted changed to true, replayed
failure session, certificate from another session, and tampered commit-reveal
transcript. Every mutation must be rejected fail-closed.

The registered Stage 6 artifact bundle is produced by:

```bash
python scripts/validate_stage6.py --replace-existing
```

The bundle is owned only by the top-level orchestrator and is published under
`artifacts/conflicts/` after all validations and checksum verification pass.
Component validation scripts write to distinct `artifacts/conflicts-component/`
directories by default and are not used to replace the registered bundle.
# Stage 7 Registry Entry

Stage 7 validation covers four feasible local-process sessions and five
infeasible fail-closed sessions. The feasible sessions preserve the Stage 5
selected profiles: `P0`, `P3`, `P4`, and `P0`. The infeasible sessions preserve
the Stage 6 conflict scenarios and abort without TLS activation or task
execution.

The registered Stage 7 artifact bundle is `artifacts/runtime/`. It contains:

- four feasible session artifacts;
- five infeasible session artifacts;
- nine deterministic state traces;
- eight sanitized feasible-process logs;
- structured adversarial runtime rejection evidence;
- structured execution-gate evidence;
- `stage7_validation.json`, `stage7_bundle_validation.json`, and
  `checksums.sha256`.

The bundle-level validator checks semantic counts, legal state transitions,
process separation evidence, repository-local OpenSSL evidence, TLS group
binding, no fallback, no weaker retry, adversarial fail-closed behavior, and
cross-artifact hashes. It is not allowed to derive success only from serialized
booleans in `stage7_validation.json`.

Regenerate the registered bundle only with:

```bash
python scripts/validate_end_to_end_stage.py --replace-existing
```

Validate it read-only with:

```bash
python scripts/validate_stage7.py --runtime-dir artifacts/runtime
```

## Stage 9 Repository-Registered Analysis

Stage 9 registers the statistical analysis and visualization plan for the
validated Stage 8 run `stage8-final-20260714-r2`. The plan is stored at
`configs/analysis/stage9_analysis_plan.yaml` and is repository-registered, not
externally preregistered.

Primary outcomes cover feasible session wall time and component latency,
fail-closed safety invariants, and concurrency scaling. Secondary outcomes
cover protocol bytes, CPU/RSS, context switches, selector fairness and regret,
conflict-certificate costs, and component batches.

Feasible method comparisons are paired by scenario, block, and repetition.
Inference uses nonparametric paired procedures, deterministic percentile
bootstrap intervals, and Holm correction. Deterministic Stage 4B preference
claims are kept separate from Stage 8 runtime measurements.
