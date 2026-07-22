# Reproducibility

This laboratory is structured so that future experiments can be reproduced from explicit configuration, captured environment facts, immutable evidence records, and versioned analysis code.

No generated or fabricated measurements are accepted. Experimental outputs must be produced by executable experiment sessions and recorded as machine-readable evidence.

The bootstrap stage provides only repository structure and environment capture. It does not create experiment results.

## OpenSSL Toolchain

The system OpenSSL is not replaced. Operating system packages can be shared by package managers, Python, Git, curl, browsers, and other tools, so replacing `/usr/bin/openssl` would make the host less reproducible and could break unrelated software. This repository instead uses a pinned, repository-local OpenSSL build when post-quantum TLS group support is needed.

The pinned local version is OpenSSL 3.5.7. The build helper downloads the official release tarball and the official SHA-256 checksum from openssl.org, verifies the checksum before extraction, runs the upstream OpenSSL test suite, and installs only under `.local/openssl-3.5.7/`.

OpenSSL's build system uses Perl and requires the `Text::Template` module while configuring and generating build files. The module may be provided by the host Perl installation, but this repository also supports a no-sudo, repository-local Perl module root at `.local/perl5/`.

Install the Perl prerequisite repository-locally without changing system Perl:

```bash
PERL_MM_USE_DEFAULT=1 cpan -l "$PWD/.local/perl5" Text::Template
```

Verify that Perl can load the repository-local module:

```bash
PERL5LIB="$PWD/.local/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}" perl -MText::Template -e 'print "$INC{\"Text/Template.pm\"}\n"'
```

Build the local OpenSSL without sudo:

```bash
make openssl-build
```

Activate it in the current shell:

```bash
source scripts/activate_local_openssl.sh
```

Activation prepends the repository-local OpenSSL `bin` and `lib` directories to `PATH` and `LD_LIBRARY_PATH`. It does not alter the Python virtual environment.

Write an environment report for the local OpenSSL:

```bash
make openssl-report
```

Validate the repository tooling:

```bash
python3 -m ruff check .
python3 -m pytest -q
python3 -m mypy src scripts
```

## Stage 9 Registered Analysis

Stage 9 is registered before analysis in
`configs/analysis/stage9_analysis_plan.yaml`. The plan binds the validated
Stage 8 run, raw manifest hash, raw checksum manifest, derived-artifact tree
hash, registered design hash, registration commit, deterministic analysis seed,
bootstrap repetitions, paired comparison unit, Holm correction policy, figure
inventory, and table inventory.

The analysis commands are explicit:

```bash
python3 scripts/register_stage9_analysis.py
python3 scripts/run_stage9_analysis.py
python3 scripts/generate_stage9_figures.py
python3 scripts/generate_stage9_tables.py
python3 scripts/validate_stage9.py
```

Ordinary tests use small fixtures or read-only validation checks. They do not
regenerate the full analysis bundle, figures, or tables. Stage 9 refuses to
overwrite an existing validated bundle unless `--replace-existing` is supplied.
Every figure has a data package with source files, filters, transformations,
metric definitions, confidence-interval method, analysis seed, dimensions,
generated filenames, provenance, and checksums.

## Stage 8 Final Campaigns

Stage 8 is registered before execution with:

```bash
python3 scripts/register_stage8_campaign.py
```

Registration writes the canonical design, environment preflight, execution
schedule, and checksums under `artifacts/campaigns/registration/`. Execution is
explicit and writes immutable JSONL under `runs/stage8/<campaign-run-id>/`:

```bash
python3 scripts/run_stage8_campaign.py
python3 scripts/resume_stage8_campaign.py --run-id <campaign-run-id>
python3 scripts/validate_stage8.py runs/stage8/<campaign-run-id>
```

Ordinary tests do not register or run the real campaigns. They exercise
temporary schedules and run directories only. Stage 8 preserves Stage 1-7
evidence hashes and refuses execution if those registered inputs change.

Stage 8 production adapters measure real command paths: feasible runs execute
commit-reveal, safe selection, signed-contract verification, execution gate,
native TLS, deterministic task request/response, and shutdown; infeasible runs
build and independently verify fresh conflict certificates, failure
transcripts, safe-abort records, and remediation reports; adversarial runs
observe a structured rejection; concurrency runs launch independent local
sessions behind a barrier; component batches execute the requested operation
count. No Stage 7 scientific measurement is copied as a Stage 8 observation.

Use the adapter preflight before the immutable run:

```bash
python3 scripts/validate_stage8_measurement_adapter.py
```

The preflight is marked `technical_preflight=true`, uses temporary directories,
and cannot write to `runs/stage8` or `artifacts/campaigns/final`.

## Stage 7 Runtime Evidence

Stage 7 runtime evidence is regenerated only by an explicit top-level command:

```bash
python scripts/validate_end_to_end_stage.py --replace-existing
```

The orchestrator stages a complete runtime bundle in a temporary sibling
directory, generates deterministic scientific JSON and sanitized process logs,
verifies state-machine semantics, cross-artifact hash bindings, adversarial
fail-closed evidence, execution-gate evidence, and checksum coverage, then
atomically replaces `artifacts/runtime/`. If validation fails, the previous
valid runtime bundle is left in place.

The read-only verifier is:

```bash
python scripts/validate_stage7.py --runtime-dir artifacts/runtime
```

It independently inspects the underlying session artifacts, state traces,
process logs, adversarial cases, execution-gate cases, and `checksums.sha256`.
Checksum success alone is not sufficient; semantic validation must also pass.

All Stage 7 CLIs use `argparse`. `--help` performs no validation and writes no
artifacts. Importing the scripts has no side effects. Ordinary `pytest` uses
deterministic temporary bundles and must not run expensive native TLS sessions.

Run the complete Stage 4B selector validation only as an explicit selector
analysis step:

```bash
make selector-nondegenerate-check
```

This writes checksummed reports under `artifacts/selection/`, including the
main selector report, complete common-safe candidate audit, non-degenerate
frontier evaluation, preference-conflict grid, and fairness comparison. It
does not modify raw calibration runs or paired relative-cost evidence.

Run Stage 5 material and validation manually only when contract evidence is
being exercised:

```bash
bash scripts/generate_agent_evidence_keys.sh
python3 scripts/validate_commit_reveal_stage.py
python3 scripts/validate_agent_evidence_keys.py
python3 scripts/validate_signed_contract_stage.py
```

The commit-reveal validation uses deterministic laboratory fixture session IDs
and nonces for reproducibility. Production nonces must be generated with the
protocol helper backed by OS randomness. Ordinary `pytest` must not regenerate
agent evidence keys.

Stage 5 signed-contract validation also uses deterministic laboratory fixture
time. Historical contracts are verified by injecting an activation time inside
each recorded lease, not by reading the day on which validation is executed.
Production adapters may call the production UTC-time helper and pass that value
explicitly to the same core protocol functions. The lease rule is
`issued_at <= activation_time < expires_at`; `expires_at` is exclusive, so
activation exactly at expiry remains rejected. This preserves expiry protection
while keeping historical validation reproducible.

Agent evidence-key validation is read-only with respect to key material. It
requires the ten-entry inventory containing both canonical algorithms,
`ML-DSA-65` and `ML-DSA-87`, for all five laboratory agents. The public
manifest stores metadata and public-key paths only. Local private-key paths are
derived from the repository-root `.local/pqtrust-crypto/agents/` layout during
laboratory signing, and private keys must not be group/world-readable.

Profile-to-contract-evidence binding is loaded from
`configs/profiles/trust_profiles.yaml`: P0, P1, P2, and P3 require `ML-DSA-65`;
P4 requires `ML-DSA-87`. Manifest, resolver, signer, and verifier all use those
canonical names. Unknown algorithms, missing entries, duplicate composite keys,
fingerprint mismatches, invalid private-key permissions, and OpenSSL failures
fail closed with structured diagnostics.

## Stage 3A Cryptographic Calibration

Stage 3A adds native C calibration binaries linked directly to the repository-local OpenSSL 3.5.7 libraries. The harness is intentionally separate from Python's `ssl` module so TLS group selection, negotiated group inspection, memory BIO byte accounting, and ML-DSA EVP operations are controlled by the same OpenSSL build captured in the environment report.

Generate laboratory-only keys and certificates only when you are ready to run the smoke gate:

```bash
make crypto-material
```

Build the native binaries explicitly:

```bash
make native-build
```

Run the functional smoke gate:

```bash
make crypto-smoke
```

The smoke artifacts under `artifacts/smoke/` are immutable checked outputs for a functional gate, not final experimental results. The batch metadata records maximum RSS as a process-level measurement only; it is not a per-operation memory value.

## Stage 3B Cryptographic Calibration

Stage 3B raw runs are launched explicitly with a caller-supplied run ID:

```bash
make crypto-calibration RUN_ID=stage3b-001
make crypto-calibration-validate RUN_ID=stage3b-001
make crypto-calibration-analyze RUN_ID=stage3b-001
```

The raw run directory is `runs/raw/crypto_calibration/<RUN_ID>/` and is checksummed after generation. Validation and analysis reports are written outside the immutable raw directory under `artifacts/calibration/<RUN_ID>/`. The campaign uses three independent replicates, block randomization, 6600 total measured records, no outlier deletion, hierarchical aggregation, and deterministic bootstrap intervals.

For completed runs, the immutable `config_snapshot.yaml` in the raw directory
is the default source of truth. `--config PATH` on validation, analysis, or
quality commands is an exact-hash check against that snapshot, not a fallback
to a repository default.

## Stage 3C Calibration Quality Control

Generate quality diagnostics for an existing raw run without modifying the raw
directory:

```bash
make calibration-quality RUN_ID=calibration-20260713-r2
```

The reports are written under `artifacts/calibration-quality/<RUN_ID>/` and
separate integrity pass/fail from timing-stability pass/fail.

Run a confirmatory campaign only as an explicit evidence collection step:

```bash
make crypto-calibration-confirmatory \
  RUN_ID=stage3c-confirmatory-001 \
  BASELINE_RUN_ID=calibration-20260713-r2
```

This uses `configs/calibration/crypto_calibration_confirmatory.yaml`, preserves
the experimental sample size and measured cases, and reuses the selected CPU
from the baseline manifest. The new seeds affect order only.

Compare compatible runs without modifying raw directories:

```bash
make calibration-compare \
  BASELINE_RUN_ID=calibration-20260713-r2 \
  CONFIRMATORY_RUN_ID=calibration-20260713-confirmatory
```

## Stage 3D Paired Relative Cost Calibration

Run the paired TLS/ML-DSA relative-cost analysis only as an explicit analysis
step:

```bash
make paired-cost-analysis \
  BASELINE_RUN_ID=calibration-20260713-r2 \
  CONFIRMATORY_RUN_ID=calibration-20260713-confirmatory
```

The default output location is
`artifacts/paired-cost-calibration/<BASELINE_RUN_ID>__<CONFIRMATORY_RUN_ID>/`.
For the canonical report name used in Stage 3D, call the script directly with
`--output-dir artifacts/paired-cost-calibration/r2-vs-confirmatory`.

The analyzer resolves each completed run from its immutable
`config_snapshot.yaml`, requires raw integrity and scientific compatibility,
preserves absolute timing-instability reports, writes checksummed artifacts
outside the raw directory, and refuses to overwrite non-empty report
directories unless `--replace-existing` is provided.

Stage 3D validates reciprocal ratios only at the raw paired-block level. Each
forward and reverse ratio must use the same run ID, replicate ID, block ID, and
metric, with finite strictly positive source values and
`math.isclose(..., rel_tol=1e-12, abs_tol=1e-12)`. The report records raw-block
reciprocity diagnostics. It does not reject independently aggregated
directional medians merely because their products are not exactly one; with an
even sample count, median averaging can break exact reciprocal equality after
aggregation. Directional estimates remain the empirical estimates, and any
reciprocal display value is explicitly labeled separately.

The baseline and confirmatory exact configuration hashes are expected to
differ because scheduling seeds and run identity differ. Their scientific
design hashes should match when the measured cases, repetition counts,
executables, TLS settings, certificate/key roles, timeout semantics, and record
design are identical.

Compare two completed campaigns without automatic pooling:

```bash
make calibration-compare \
  BASELINE_RUN_ID=calibration-20260713-r2 \
  CONFIRMATORY_RUN_ID=stage3c-confirmatory-001
```

Set `CREATE_COMBINED_SUMMARY=1` only when an explicit six-replicate summary is
intended and both runs pass integrity.

Quality and comparison tools refuse to overwrite non-empty report directories
unless `--replace-existing` is supplied. Replacement is staged in a sibling
temporary directory and then swapped atomically after JSON and checksums are
written.

## Schemas and Catalog Validation

Export deterministic JSON Schemas for the typed protocol models:

```bash
python3 scripts/export_schemas.py --output-dir schemas
```

Validate the initial P0-P4 trust-profile catalog against the captured OpenSSL environment report:

```bash
python3 scripts/validate_profile_catalog.py \
  --catalog configs/profiles/trust_profiles.yaml \
  --environment-report artifacts/environment/environment_report.json \
  --output artifacts/environment/profile_catalog_validation.json
```

The catalog check verifies that the catalog loads, contains exactly P0-P4, uses TLS groups positively available in the real environment report, runs against OpenSSL at least 3.5, has `pq_tls_ready` set to true, and still contains no measured `ResourceEnvelope` values.

The current P0-P4 catalog is not an experiment result and contains no generated performance values. It is a typed configuration artifact for the next protocol stages.

Return to the system OpenSSL by opening a fresh terminal, or restore `PATH` and `LD_LIBRARY_PATH` to their previous values in the current shell.

## Policy Stage Validation

Validate the deterministic policy compiler configuration:

```bash
python3 scripts/validate_policy_stage.py \
  --catalog configs/profiles/trust_profiles.yaml \
  --agents-dir configs/agents \
  --policies-dir configs/policies \
  --scenarios-dir configs/scenarios \
  --output artifacts/policy/policy_stage_validation.json
```

The report includes a timestamp, hashes, matched rules, local safe sets,
common-safe-set sanity checks, and profile-level rejection categories. The
timestamp is the only intentionally non-deterministic field. The report does
not contain latency, CPU, memory, energy, utility, regret, or empirical
effectiveness results. It is a deterministic compiler validation artifact, not
a bilateral selector result.

## Stage 4A Selector Validation

Validate selector code quality without running the real selector-stage
validation:

```bash
python3 -m ruff check .
python3 -m pytest -q
python3 -m mypy src scripts
```

Run the selector-stage validation only as an explicit manual step:

```bash
python3 scripts/validate_selector_stage.py \
  --catalog configs/profiles/trust_profiles.yaml \
  --agents-dir configs/agents \
  --policies-dir configs/policies \
  --preferences-dir configs/preferences \
  --scenarios-dir configs/scenarios \
  --cost-evidence-dir artifacts/paired-cost-calibration/r2-vs-confirmatory \
  --output artifacts/selection/selector_stage_validation.json
```

The script writes the selector validation report atomically and records
`artifacts/selection/checksums.sha256`. It does not modify raw calibration
runs. The report includes local safe sets, common safe sets, Pareto frontiers,
selected profiles, regret tables, uncertainty sensitivity, weight sensitivity,
baseline selections for later comparison, and validation errors.
## Stage 6 Reproduction

Stage 6 validation is split from ordinary tests. The code checks are:

```bash
ruff check .
pytest -q
mypy src scripts
```

Conflict and safe-abort artifacts are generated only when explicitly requested:

```bash
python scripts/validate_stage6.py --replace-existing
```

The Stage 6 orchestrator stages the complete bundle in a temporary sibling
directory, runs conflict certificate validation, safe-abort validation,
feasible-scenario regression, adversarial validation, certificate generation,
failure transcript generation, abort record generation, remediation report
generation, checksum generation, and checksum verification, and replaces
`artifacts/conflicts/` only after the complete bundle succeeds. The component
scripts remain usable for isolated development, but their default outputs are
under `artifacts/conflicts-component/` so they cannot erase each other's
artifacts. Stage 6 generation does not regenerate keys, calibration data,
selector evidence, or Stage 5 protocol artifacts.

The checksum file proves byte integrity of the files that were staged. It does
not prove the bundle is scientifically complete. Before replacement the
orchestrator also requires five certificates, five failure transcripts, five
abort records, five remediation reports, five safe-abort scenarios, four
feasible-regression scenarios, fifteen adversarial cases, exact scenario ID
sets, unique IDs, distinct report payloads, valid certificate-to-transcript and
transcript-to-abort references, independently recomputed IUS taxonomies, and
passing component reports.

The feasible regression report reads the existing Stage 5 signed-contract
artifacts, recomputes or verifies their signed-contract hashes, and records
that Stage 6 did not change selected profiles or create infeasible-session
artifacts. Stage 5 protocol files must remain byte-identical across Stage 6
generation attempts.
# Stage 7 Runtime Reproducibility

Stage 7 runtime artifacts are generated only by explicit commands. Deterministic
scientific JSON uses fixture session IDs, existing Stage 5 contract hashes,
existing Stage 6 conflict artifacts, and explicit activation times. Runtime
process logs may contain host-specific process IDs and timings and are stored
separately under `artifacts/runtime/process_logs/`.
