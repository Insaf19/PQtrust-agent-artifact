# PQTrust-Agent

Reproducibility artifact for the paper:

**PQTrust-Agent: Policy-Compiled Post-Quantum Trust Contracts for Web-of-Agents Communications**

## Overview

PQTrust-Agent is a constraint-first bilateral authorization protocol for Web-of-Agents communications.

Each endpoint independently compiles its capabilities and hard policy requirements into a local safe set. Selection is performed only over the common safe profiles. The selected profile is bound to a dual ML-DSA-signed task contract and checked by a stateful execution gate before exact-group TLS 1.3 and task execution.

Infeasible negotiations terminate with a fail-closed abort and a verifiable subset-minimal conflict certificate. The prototype does not silently retry with a weaker profile.

## Artifact scope

The repository contains:

- the PQTrust-Agent Python implementation;
- typed schemas and validated profile catalogs;
- policy compilation and Z3-based conflict analysis;
- commit-reveal negotiation and deterministic minimax-regret selection;
- dual-signed contracts and the execution gate;
- native TLS and ML-DSA benchmark programs;
- the frozen final Stage 8 campaign;
- Stage 9 statistical analysis and validation tools;
- derived tables, statistics, checksums, and provenance records.

The frozen campaign contains 1,040 observations:

- 480 feasible observations;
- 150 infeasible observations;
- 200 adversarial trials;
- 100 concurrency observations;
- 110 component benchmark batches.

The two offline post-hoc audits reported in the paper are kept separate from the pre-specified 1,040-observation campaign.

## Evaluated environment

The submitted-paper measurements were collected on:

- Ubuntu 24.04;
- Linux x86-64;
- Python 3.12;
- OpenSSL 3.5.7;
- Z3 4.16.

Performance values are host-specific. Another machine should reproduce the protocol invariants, deterministic selector decisions, observation counts, and offline analyses, but not necessarily identical wall-clock latency.

## Repository structure

```text
configs/       Experiment, policy, profile, and analysis configurations
docs/          Protocol and evaluation documentation
experiments/   Experiment definitions
native/        Native TLS and ML-DSA benchmark sources
runs/          Frozen raw calibration and Stage 8 campaign data
schemas/       Exported data schemas
scripts/       Execution, analysis, and validation commands
specs/         Protocol specifications
src/           PQTrust-Agent implementation
tests/         Unit, property-based, and integration tests
artifacts/     Derived results, tables, validation reports, and provenance
```

## Quick setup

Create an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
make artifact-setup
```

## Validate the frozen artifact

```bash
make artifact-check
```

This command checks the source code, tests, frozen Stage 8 campaign, and Stage 9 analysis bundle.

## Development checks

```bash
make check
```

This runs:

- Ruff static checks;
- MyPy type checks;
- Pytest tests.

## Rendered-figure policy

The internal Stage 9 pipeline generated supplementary diagnostic figure
renders that were not used in the submitted paper. Those PNG, PDF, and SVG
renders are intentionally omitted from this public artifact.

Their numerical data packages, captions, metadata, provenance records,
checksums, statistical results, and generation scripts remain available.

## Reproduce the paper results

Run the complete offline validation and post-hoc reproduction workflow:

```bash
make reproduce-paper
```

This command runs static checks, type checking, the test suite, validation of
the frozen 1,040-observation Stage 8 campaign, validation of the Stage 9
analysis bundle, the 566,280-report manipulability audit, and the constructed
15-profile selector audit.

The command validates and recomputes the principal reported results without
repeating host-dependent TLS and ML-DSA performance measurements.

## Full experimental rerun

A full rerun requires a compatible Linux x86-64 environment and a local OpenSSL 3.5.7 build supporting the evaluated TLS 1.3 groups.

Build and inspect the local cryptographic environment with:

```bash
make openssl-build
make openssl-report
make native-build
```

The full calibration and Stage 8 campaign are deliberately not executed by ordinary tests because they are significantly more expensive and generate new host-specific measurements.

## Reproducibility boundary

The repository distinguishes three operations:

1. **Artifact validation:** verifies the integrity of the frozen inputs and derived results.
2. **Offline reproduction:** recalculates the paper's deterministic and statistical results from the frozen data.
3. **Full rerun:** executes new TLS, ML-DSA, protocol, concurrency, and component measurements on the current host.

Absolute timing measurements are not expected to be identical across machines.

Files whose names contain `registration` preserve repository-frozen design and analysis metadata. They do not imply external third-party preregistration.

## Security notice

Do not commit private keys, API tokens, `.env` files, user credentials, or machine-specific secrets.

Local cryptographic material must be generated through the provided scripts and remains excluded from version control.

## Authors

- Yulliwas Ameur
- Insaf Imene Lasledj
- Samia Bouzefrane
