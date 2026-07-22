# Final Experimental Campaigns

Stage 8 registers the final PQTrust-Agent experimental campaigns before any
measured execution. The fixed design is stored in
`configs/campaigns/stage8_final_campaign.yaml` and is canonically hashed during
registration. The runner refuses execution if the repository is dirty, the
configuration hash changes, Stage 1-7 evidence hashes change, repository-local
OpenSSL 3.5.7 is unavailable, required native binaries are missing, or the
requested completed run ID already exists.

## Registered Design

The campaign contains five registered families:

- Feasible sessions: four scenarios, four safe selection rules, 30 repetitions
  each, three blocks of ten repetitions.
- Infeasible sessions: five scenarios, 30 repetitions each.
- Adversarial trials: the 20 Stage 7 runtime attacks, 10 trials each.
- Concurrency trials: two feasible scenarios at concurrency 1, 2, 4, 8, and 16,
  with 10 repetitions for each scenario and level.
- Component overhead batches: 11 components, 100 operations inside each of 10
  independent processes.

Methods are randomized within each feasible block by the registered deterministic
seed. Paired comparison identifiers are attached to every feasible observation.
The schedule is written at registration time as
`artifacts/campaigns/registration/execution_schedule.json` and is immutable
after the first measured observation.

## Raw And Derived Evidence

Raw campaign output is written under one ignored run directory:

```text
runs/stage8/<campaign-run-id>/
```

Each JSONL row is appended and flushed after a completed observation. Completed
observation IDs are never rewritten, duplicates are rejected, and interrupted
runs remain incomplete until every scheduled observation exists. `RUN_COMPLETE`
is created only by atomic finalization after validation passes.

The runner uses typed production measurement adapters for the five registered
observation kinds: feasible sessions, infeasible sessions, adversarial trials,
concurrency trials, and component batches. Unknown kinds fail closed. The
adapters call the repository protocol/runtime modules and native binaries; they
do not fabricate, synthesize, estimate, randomly generate, or copy Stage 7
measurements.

Raw timings are captured with `time.perf_counter_ns()` and
`time.process_time_ns()`. Resource fields come from `resource.getrusage()` for
the current process and completed child processes. Linux `ru_maxrss` is recorded
as KiB. Metrics that cannot be read reliably are stored as `null` plus an
explicit `unavailable_reason`.

Derived artifacts are generated only after a complete raw run and contain
inventory summaries, validation reports, failure inventory, environment capture,
provenance, and checksums. They do not contain publication figures or final
inferential statistics; Stage 9 performs analysis and visualization.

## Failure Handling

Failures are preserved and classified as protocol rejection, expected
adversarial rejection, environment failure, process failure, timeout,
measurement failure, or integrity failure. Valid slow observations are not
discarded. Missing measurements must be recorded as `null` with an explicit
reason, not invented.

Validation fails when a required observation is missing, an unexpected feasible
session fails, an infeasible session reaches TLS or task execution, an attack is
accepted, a weaker retry is attempted, a checksum fails, or the registered
design changes.

## Warm-Up, Randomness, And Resume

Before the first measured observation, the runner performs exactly one
unmeasured TLS warm-up for each registered TLS group and records completion in
the run manifest. Warm-ups are not written to raw JSONL and are not repeated by
resume once the manifest records completion.

The schedule order remains deterministic. Measured sessions use fresh
production-style randomness for public session identifiers, commit nonces, and
contract identifiers. Secret nonce material and private keys are never written
to raw campaign JSONL.

Resume may append only missing scheduled observations. Existing rows are
validated, duplicate IDs are rejected, and the run manifest must match the
registered commit, design hash, registration artifact hash, and schedule hash.
Runs created under a different registration commit or artifact are not resumed.

## Technical Preflight

`scripts/validate_stage8_measurement_adapter.py` executes one isolated
technical sample for each adapter path in a temporary directory, including a
concurrency level of 2 and a reduced component operation count. It is not a
pilot campaign, never writes into `runs/stage8` or `artifacts/campaigns/final`,
and marks outputs with `technical_preflight=true`.

## Limitations

Stage 8 is a single-machine local laboratory campaign. It can measure local
process behavior, local TLS execution, and controlled concurrency, but it does
not claim wide-area network behavior or multi-host production deployment
performance. The design forbids adaptive stopping and post-hoc method changes.

## Commands

```bash
python3 scripts/register_stage8_campaign.py
python3 scripts/run_stage8_campaign.py
python3 scripts/resume_stage8_campaign.py --run-id <campaign-run-id>
python3 scripts/validate_stage8.py runs/stage8/<campaign-run-id>
python3 scripts/analyze_stage8_inventory.py runs/stage8/<campaign-run-id>
```
