# Stage 3B/3C Cryptographic Calibration Protocol

Stage 3B calibrates real cryptographic costs for the PQTrust-Agent prototype. It is not the final end-to-end agent experiment and does not include bilateral negotiation, regret selection, commit-reveal, signed trust contracts, network services, attack campaigns, plots, tables, endpoint emulation, or energy claims.

## Hypotheses and Quantities

The campaign measures TLS 1.3 memory-BIO handshake latency, process CPU time, and encrypted handshake bytes for five configured TLS groups. It separately measures ML-DSA-65 and ML-DSA-87 sign time, verify time, and signature size for 512, 2048, and 8192 byte deterministic messages.

The measurements are calibration evidence for later protocol stages. Smoke measurements are excluded from scientific summaries because they are functional gates with small repetition counts and different payload coverage.

## Replicates and Randomization

The campaign uses three independent replicates to expose run-to-run instability instead of hiding it inside a single pooled sample. Each TLS replicate performs 30 warmups per group and 200 randomized measured blocks. Each block contains X25519, X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, and SecP384r1MLKEM1024 exactly once, yielding 1000 measured TLS records per replicate and 3000 total.

Each ML-DSA replicate performs 30 warmups per algorithm/message-size case and 200 randomized measured blocks. Each block contains all six ML-DSA cases exactly once, yielding 1200 measured records per replicate and 3600 total.

The fixed seeds in `configs/calibration/crypto_calibration.yaml` control scheduling and deterministic benchmark messages only. They do not control cryptographic key generation.

## CPU Affinity and Machine State

The runner selects one permitted CPU core and pins each native benchmark process with `taskset` when available. If affinity cannot be applied, the raw evidence records that fact. TLS and ML-DSA benchmark processes are never run concurrently.

The runner does not modify CPU governors, turbo settings, kernel configuration, or any system-wide setting. Before and after each replicate it records UTC and monotonic timestamps, affinity, load, memory, CPU model, kernel, OpenSSL runtime version, native executable hashes, readable governor/frequency data, readable thermal-zone temperatures, Python version, Git commit and dirty state, and the configuration hash. Optional frequency and thermal files are recorded as null or omitted when unreadable.

## Raw Evidence

Raw evidence is written under `runs/raw/crypto_calibration/<run-id>/`. The runner refuses to overwrite an existing run directory. Files are written atomically, native stderr is preserved even when empty, and `checksums.sha256` is generated and verified last. After checksum generation the raw run directory is immutable; Stage 3B validation and analysis outputs are written under `artifacts/calibration/<run-id>/`, and Stage 3C quality reports are written under `artifacts/calibration-quality/<run-id>/`.

Valid observations are never fabricated, smoothed, replaced, or deleted. Outliers are diagnostics only.

Every completed raw run contains `config_snapshot.yaml` and
`run_manifest.json`. Auditing tools use the raw-run snapshot as the source of
truth. Passing `--config PATH` does not replace the snapshot; it requires the
external file to have the same exact configuration hash as the snapshot.

## Validation

Raw validation checks the exact replicate count, exact record counts, balanced blocks, contiguous unique sequence numbers, TLS negotiated-group consistency, TLS version and cipher suite, certificate result, session reuse, positive timing and byte counts, TLS success fields, ML-DSA sign/verify positivity, verification success, negative self-tests, signature sizes, OpenSSL/local-library evidence, checksums, finite numbers, and absence of missing or unexpected cases.

Any failed invariant returns a non-zero validator status. Outliers are not discarded.

## Analysis

Statistics use only the Python standard library. For each case and replicate the analysis reports count, minimum, maximum, arithmetic mean, median, sample standard deviation, MAD, p05, p25, p75, p95, and p99. Quantiles use documented linear interpolation between closest ranks with `h=(n-1)*p+1`.

Campaign-level central estimates are hierarchical: compute the median within each replicate, then report the median of the three replicate medians. The analysis also reports the minimum and maximum replicate medians, between-replicate range, and all replicate medians. Byte and signature sizes report whether every observation is identical; variable byte data are not treated as constants.

The deterministic hierarchical bootstrap samples three replicates with replacement, samples observations within each sampled replicate with replacement, computes the campaign median, repeats 10,000 times with seed 20260801, and reports percentile 95% intervals. Normal-theory latency intervals are not used.

Stage 3C quality diagnostics are separate from the Stage 3B summaries. They verify raw checksums before analysis, preserve all observations, report zero-MAD outlier rules as undefined rather than labeling every non-median value, compute 20-block first/last window drift, compute Theil-Sen timing trends, audit machine state, and apply a transparent quality gate. Replicate-instability warnings still use the fixed 10% relative-range threshold. Warnings do not alter summaries.

The confirmatory configuration is `configs/calibration/crypto_calibration_confirmatory.yaml`. Its new seeds change scheduling order only; the scientific design hash excludes scheduling seeds and run identifiers, while the exact configuration hash includes them.

The exact hash uses domain-separated RFC 8785 canonical JSON over the complete
configuration. The scientific-design hash uses a separate domain and removes
only run identity, TLS and ML-DSA scheduling seeds, and replicate display
identifiers. Exact hash inequality is expected between baseline and
confirmatory runs when only seeds differ; it is not by itself scientific
incompatibility.

## Stage 3D Paired Relative Analysis

Stage 3D consumes existing immutable runs only. It resolves each run from its
own `config_snapshot.yaml`, requires raw integrity and scientific
compatibility, and refuses non-empty output directories unless
`--replace-existing` is supplied.

TLS analysis pairs records by run, replicate, block, and TLS group. Each block
must contain exactly one successful observation for all five catalog profiles.
The analyzer computes within-block ratios, absolute differences from P0, log
timing ratios, all ordered profile-pair comparisons, hierarchical replicate and
run medians, and a deterministic paired hierarchical bootstrap with seed
`20260841`.

The Stage 3D selector artifact is calibrated evidence, not a policy-specific
cost vector. ML-DSA paired comparisons are reported separately by message size
because canonical contract and manifest payload sizes have not yet been
measured.

## Limitations

Memory-BIO TLS measurements isolate the cryptographic handshake path from TCP scheduling, kernel queues, routing, and network impairment. Later stages must measure real A2A networking and `tc/netem` scenarios separately.
