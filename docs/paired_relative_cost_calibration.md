# Paired Relative Cost Calibration

Stage 3D uses the randomized complete-block structure already present in the
two immutable calibration campaigns:

- `calibration-20260713-r2`
- `calibration-20260713-confirmatory`

Both runs pass raw integrity and are scientifically compatible. Their absolute
timing stability exceeds the fixed 10% threshold, and that instability remains
reported. Stage 3D does not repair, delete, detrend, or suppress the raw
absolute observations.

## Why Absolute Timing Varied

The TLS and ML-DSA benchmarks run on a general-purpose host. Even with pinned
native binaries, a repository-local OpenSSL build, serialized benchmark
processes, and recorded CPU affinity, the machine can still vary because of CPU
frequency behavior, scheduler noise, thermal state, background load, memory
state, and other host effects. Stage 3C treats this as measured systems
variation, not as evidence corruption.

## Why Pairing Is Valid

Each TLS replicate is a randomized complete-block design. Every measured TLS
block contains exactly one successful observation for each configured group:
X25519, X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, and
SecP384r1MLKEM1024. Randomization changes execution order inside a block, so
Stage 3D pairs by run, replicate, block, and TLS group. It never pairs by
sequence number or `position_in_block`.

Within-block ratios compare each profile to P0 in the same run, replicate, and
block. That denominator shares much of the same short-term machine state, so
common-mode variation is reduced without changing the retained absolute
measurements.

Stage 3D also validates all ordered profile-pair ratios at the raw paired-block
level. For every run, replicate, block, metric, and distinct profile pair
`Pi/Pj`, the analyzer computes `value(Pi, block) / value(Pj, block)` and the
reverse ratio from the same two source records. Both source values must be
finite and strictly positive, and the reciprocal product must satisfy
`math.isclose(product, 1.0, rel_tol=1e-12, abs_tol=1e-12)`. Missing profiles,
duplicate profile observations, mismatched block identity, zero, negative,
NaN, or infinite values fail validation before report artifacts are published.

## Profile Mapping

The TLS selector evidence uses the catalog mapping:

- P0: X25519
- P1: X25519MLKEM768
- P2: SecP256r1MLKEM768
- P3: MLKEM768
- P4: SecP384r1MLKEM1024

The analyzer verifies this mapping against the profile catalog before writing
artifacts.

## Aggregation

Stage 3D does not pool all 1200 paired TLS ratios directly. For every profile
and metric it computes:

1. the median ratio inside each replicate;
2. one run-level median from the three replicate medians;
3. one final relative estimate as the median of the two run-level medians.

The reports retain all six replicate medians, both run medians, the final
relative estimate, the replicate median range, and the baseline-versus-
confirmatory relative difference.

Reciprocal equality is not imposed on independently aggregated medians. With an
even number of positive observations, Python's median definition averages the
two central values, so `median(x/y) * median(y/x)` can differ from exactly one
even when every raw paired-block reciprocal product is exactly one. Pairwise
matrix estimates are therefore directional empirical estimates. If a reciprocal
display is needed, the report labels it separately as
`symmetric_display_estimate`; it must not be treated as a replacement for
`directional_hierarchical_estimate`.

The pairwise matrix includes a raw-block `reciprocity_diagnostics` section with
the checked count, failing count, maximum absolute and relative product error,
the strict tolerance, and the validation result.

## Paired Bootstrap

The paired bootstrap is hierarchical and deterministic. It samples runs with
replacement, samples replicates within each sampled run, samples paired blocks
within each sampled replicate, and computes the median paired ratio. Resampling
keeps all profile observations in a selected block together; profiles are never
resampled independently. The seed is `20260841` and the production iteration
count is 10,000.

## Stability Gate

The 10% threshold is unchanged. For timing metrics, paired relative cost passes
only when the baseline and confirmatory run-level ratios differ by at most 10%,
the six-replicate relative range is at most 10%, the bootstrap interval is
strictly positive, no paired blocks are missing, and integrity plus scientific
compatibility pass.

The quality gate reports absolute timing stability separately from paired
relative timing stability. Selector cost evidence is usable only when all
profiles and required selector timing metrics pass; a single passing profile is
not enough.

## Evidence Versus Policy Weights

`selector_tls_cost_evidence.json` is calibrated evidence, not a final
policy-specific cost vector. It includes relative TLS wall time, CPU time, and
handshake bytes with source hashes and usability status. It does not include
energy, per-operation memory, ML-DSA contract cost, policy weights, scalar
utility, bilateral negotiation, or minimax regret.

P0-referenced selector ratios are always computed inside the same complete
block as `value(Pi, block) / value(P0, block)`. P0 ratios are emitted as exactly
`1.0`, P0 differences as exactly `0.0`, and no campaign-level denominator is
used. All complete TLS blocks are retained; raw observations are never removed
to create matrix symmetry.

## ML-DSA Remains Separate

ML-DSA records are also randomized in complete blocks over algorithm and
message size. Stage 3D reports paired ML-DSA-65 versus ML-DSA-87 comparisons
for each message size independently, covering signing time, verification time,
and signature size.

ML-DSA is not inserted into `selector_tls_cost_evidence.json`. The canonical
contract and manifest payload sizes have not yet been measured, so contract
cost remains separate from TLS selector evidence.

## Selector Consumption

Stage 4A treats `selector_tls_cost_evidence.json` as trusted only after
verifying `checksums.sha256`, `relative_cost_quality_gate.json`, and
`analysis_manifest.json`. The selector requires raw integrity, scientific
compatibility, exactly 1200 complete paired TLS blocks, matching source run
IDs, matching raw checksums, the current catalog hash, the scientific-design
hash, exactly P0-P4, and TLS group mappings matching the current catalog.

The selector continues to preserve the failed absolute timing-stability result
as metadata. The measured cost vector remains limited to paired TLS wall time,
process CPU time, and handshake bytes.
