# Calibration Quality Control

Stage 3C preserves the first complete calibration campaign,
`calibration-20260713-r2`, because its raw evidence passed integrity checks:
checksums, record counts, block balance, cryptographic success fields, local
OpenSSL evidence, and invariants. Timing-instability warnings are quality
diagnostics, not a reason to delete or rewrite raw observations.

Integrity and timing stability are separate gates. Integrity asks whether the
records are authentic, complete, and internally valid. Timing stability asks
whether replicate medians, windowed drift, bootstrap interval quality, and
machine state make the campaign suitable as a stable selector-cost input.

## Configuration Source of Truth

Completed raw runs are self-describing. Validation, analysis, quality audit,
and cross-run comparison load `<raw-run>/config_snapshot.yaml` by default and
reject duplicate YAML keys before validating the typed configuration. An
optional `--config PATH` is only a consistency assertion: the external file and
the raw-run snapshot must have the same exact configuration hash. The tools do
not silently fall back to the repository baseline configuration when auditing a
completed run.

Two hashes are reported. `exact_configuration_hash` covers every configuration
field, including scheduling seeds, run identifiers, replicate identifiers,
warmups, measured blocks, executable paths, timeout values, and run-order
details. `scientific_design_hash` excludes only non-design run identity,
scheduling seeds, and replicate display identifiers. It retains TLS groups,
ML-DSA algorithms, message sizes, warmups, measured blocks, replicate count,
TLS version, cipher suite, certificate and key roles, timeout semantics,
benchmark executable identities, measured variables, and case definitions.

## Zero-MAD Outliers

The 3xMAD rule is defined only when MAD is positive. When MAD is zero, every
non-median value would otherwise be labeled as an outlier even if values differ
by only one to three bytes. Stage 3C reports `method_status:
undefined_zero_mad`, null outlier count and proportion, and the distinct value
count, minimum, maximum, and range. No outliers are deleted in either case.

## Windowed Drift

The previous single first-block versus last-block diagnostic was too sensitive.
Stage 3C compares the median of blocks 0-19 with the median of blocks 180-199
for each case, metric, and replicate. It reports each replicate's relative
change and then summarizes the median, minimum, maximum, positive direction
count, negative direction count, and same-direction count. A warning requires
both an absolute median relative change above 10% and at least two replicates
with the same direction.

## Theil-Sen Trend

For each replicate and timing metric, Stage 3C computes a deterministic
standard-library Theil-Sen slope over block index and block-level medians. The
report includes slope per block, normalized slope relative to the replicate
median, expected relative change over 200 blocks, and direction. This is only a
diagnostic; the raw observations are not detrended or corrected.

## Machine State

The machine-state audit reads every replicate `pre_state.json` and
`post_state.json`. It reports selected CPU, applied affinity, load averages,
available memory, governor, frequency, thermal values, changes between pre and
post state, and missing-value fields. Missing frequency or temperature values
remain null or empty; the audit does not fabricate them and does not claim
causality.

## Confirmatory Campaign

The confirmatory configuration is
`configs/calibration/crypto_calibration_confirmatory.yaml`. It preserves the
groups, algorithms, message sizes, warmups, measured blocks, three replicates,
cipher suite, certificate material, native executables, and statistical design.
The new TLS and ML-DSA seeds affect scheduling order only.

Run the confirmatory campaign only when intentionally collecting new evidence:

```bash
make crypto-calibration-confirmatory \
  RUN_ID=calibration-confirmatory-001 \
  BASELINE_RUN_ID=calibration-20260713-r2
```

The command reuses the selected CPU from the baseline manifest and fails if that
CPU is not currently available or affinity cannot be applied.

## Cross-Run Comparison

`scripts/compare_crypto_calibrations.py` compares baseline and confirmatory
runs only when the seed-independent scientific design hash, catalog hash,
OpenSSL version, benchmark executable hashes, and case definitions match. Exact
configuration hashes are still reported and are expected to differ when only
scheduling seeds differ.

The script reports campaign medians, absolute and relative differences,
confidence intervals, interval overlap, and whether each campaign is stable
within the 10% replicate-range threshold. It never pools campaigns by default.
`--create-combined-summary` is required for a six-replicate hierarchical
summary, and that summary preserves all replicate identities.

Quality and comparison report directories are protected from partial overwrite.
By default the tools refuse to write into a non-empty output directory. With
`--replace-existing`, output is generated in a sibling temporary directory,
JSON and checksums are written there, and the previous report directory is
atomically replaced only after generation succeeds. Raw run directories are not
modified.

## Selector-Cost Use

A calibration can be used for exploratory analysis when integrity passes and
bootstrap interval quality is reported. Use as final selector cost requires
integrity pass, replicate relative range at or below 10%, absent windowed drift
warnings, and bootstrap relative-width reporting. A timing-stability failure
does not retroactively invalidate the raw run.

The combined reports therefore distinguish pipeline validity, raw integrity,
scientific-design compatibility, and measured timing stability. Genuine
instability warnings remain visible and must not be converted into passing
flags.

## Stage 3D Paired Relative Costs

Stage 3D adds `scripts/analyze_paired_crypto_costs.py` for the compatible
`calibration-20260713-r2` and `calibration-20260713-confirmatory` campaigns.
It preserves the absolute timing-instability result while exploiting the
randomized complete-block design: each retained TLS block must contain exactly
one successful observation for P0-P4, and ratios are computed against P0 inside
the same run, replicate, and block.

The paired quality gate keeps the 10% threshold, but applies it to run-level
relative ratios and six-replicate relative ranges. The output evidence is
calibrated TLS selector-cost evidence only; policy weights, final utility,
bilateral negotiation, minimax regret, and ML-DSA contract costs remain outside
this stage.

Reciprocity validation is a raw paired-block integrity check, not an aggregate
matrix check. For each same-run, same-replicate, same-block profile pair and
metric, both source values must be finite and strictly positive, and the
forward and reverse products must be close to one with `rel_tol=1e-12` and
`abs_tol=1e-12`. The analyzer reports the diagnostic counts and maximum product
errors.

The quality gate does not require independently aggregated directional medians
to multiply to one. Even-sample medians average the two central observations,
which can break exact reciprocal equality after aggregation while every raw
paired-block ratio remains reciprocal. Directional hierarchical estimates stay
primary; any reciprocal display value is separately labeled
`symmetric_display_estimate`.
