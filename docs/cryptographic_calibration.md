# Cryptographic Calibration Harness

Stage 3A introduces a native calibration harness for functional smoke testing of the cryptographic mechanisms planned for PQTrust-Agent. Stage 3B uses the same native mechanisms for a rigorous calibration campaign. Neither stage creates paper plots, rankings, network conclusions, endpoint-resource emulation, or energy claims.

## Native Harness

The TLS and ML-DSA harnesses are written in C and link directly against the repository-local OpenSSL 3.5.7 installation under `.local/openssl-3.5.7/`. Python's `ssl` module is not used because it does not expose the needed TLS 1.3 group controls, negotiated group checks, memory BIO byte accounting, or ML-DSA EVP operations with the required precision.

Build the native binaries explicitly:

```bash
make native-build
```

The build script verifies OpenSSL 3.5.7, embeds an rpath to the repository-local library directory, prints `ldd`, and fails if `libssl` or `libcrypto` resolve outside the repository prefix. It never changes system libraries.

Optional sanitizer builds are separate from the optimized binaries:

```bash
make -C native sanitize OPENSSL_PREFIX="$PWD/.local/openssl-3.5.7"
```

Run one sanitized X25519 handshake with existing laboratory material:

```bash
.build/native-sanitize/tls_handshake_bench --groups X25519 --certificate .local/pqtrust-crypto/server_p256.cert.pem --private-key .local/pqtrust-crypto/server_p256.key.pem --ca-certificate .local/pqtrust-crypto/lab_ca_p256.cert.pem --warmups 0 --repetitions 1 --seed 1 --output /tmp/pqtrust-x25519-sanitize.jsonl
```

## Laboratory Material

Generate laboratory-only cryptographic material explicitly:

```bash
make crypto-material
```

The material lives under `.local/pqtrust-crypto/` and is ignored by Git. It contains an ECDSA P-256 laboratory CA, an ECDSA P-256 server certificate for `localhost` and `127.0.0.1`, and ML-DSA-65/ML-DSA-87 application evidence keys. The manifest at `artifacts/environment/lab_crypto_material_manifest.json` contains metadata and hashes only, not private-key bytes.

The same ECDSA certificate and TLS cipher suite are used for every TLS group so the smoke gate changes only the key-establishment group. Hybrid and ML-KEM TLS groups address key establishment; endpoint authentication remains classical ECDSA in this stage. Application-level ML-DSA evidence is calibrated separately.

## TLS Smoke Semantics

`tls_handshake_bench` performs real TLS 1.3 client/server handshakes over paired memory BIOs. Memory BIOs isolate the cryptographic handshake path from TCP scheduling, kernel queueing, routing, and `tc/netem` effects. Real TCP and network emulation measurements are intentionally deferred to a later stage.

Tickets, resumption, early data, and session caching are disabled so every measured record is a fresh full handshake. The harness fixes `TLS_AES_256_GCM_SHA384`, configures exactly one supplied TLS group on both endpoints, verifies the laboratory CA, enables hostname verification for `localhost`, and records the negotiated group and TLS version.

OpenSSL exposes negotiated TLS group names through `SSL_get0_group_name()`. The returned pointer is borrowed from the live `SSL` object, so the harness copies the client and server group names into fixed-size owned buffers before any `SSL_free()` call. JSON output is written only from those owned strings. The benchmark also copies the TLS version and cipher-suite strings before freeing the client object.

A TLS record is successful only if both endpoints complete a fresh TLS 1.3 handshake, the requested and negotiated groups match exactly ignoring ASCII case, the client and server negotiated-group names agree, the cipher suite is `TLS_AES_256_GCM_SHA384`, certificate verification succeeds, the session is not reused, and both encrypted handshake byte counters are positive. Group comparison is case-insensitive because OpenSSL 3.5 group tokens are case-insensitive, but it is still exact token equality: `X25519` and `x25519` match, while `X25519` and `X25519MLKEM768` do not. The requested group remains the experiment input, and the negotiated group remains the copied OpenSSL output.

Exact encrypted handshake bytes are counted while transferring pending bytes between each endpoint's write BIO and the peer's read BIO. The C executable emits one JSON object per measured handshake and no summary statistics.

The owned-string fix changes benchmark correctness and validation safety only. It does not add, remove, or reinterpret scientific measurements.

## ML-DSA Smoke Semantics

`mldsa_bench` loads existing ML-DSA-65 and ML-DSA-87 keys through OpenSSL EVP. It signs deterministic calibration messages derived from SHA-256 inputs and verifies each produced signature. A deliberately modified message is rejected during the negative self-test. Key generation is not benchmarked.

## Memory Semantics

The native programs emit batch metadata files containing process maximum resident set size from `getrusage`. Maximum RSS is a process-level batch measurement. It is not a per-handshake, per-signature, or per-verification peak memory value.

## Smoke Gate

Run the functional smoke gate explicitly:

```bash
make crypto-smoke
```

The default output directory is `artifacts/smoke/crypto_smoke/`. The orchestrator refuses to overwrite a non-empty output directory, validates the environment report and P0-P4 catalog, verifies laboratory material, runs the two native binaries with small fixed smoke schedules, validates every raw JSONL record, and writes checksums.

The smoke summary contains only counts, observed sets, validation errors, and pass/fail facts. It deliberately excludes means, medians, percentiles, comparisons, gains, rankings, and statements suitable for the paper.

## Stage 3B Campaign

The Stage 3B protocol is specified in `docs/crypto_calibration_protocol.md` and configured by `configs/calibration/crypto_calibration.yaml`. The campaign measures five TLS groups and six ML-DSA algorithm/message-size cases across three replicates with 30 warmups per case and 200 randomized measured blocks per replicate.

Run, validate, and analyze with:

```bash
make crypto-calibration RUN_ID=stage3b-001
make crypto-calibration-validate RUN_ID=stage3b-001
make crypto-calibration-analyze RUN_ID=stage3b-001
```

Analysis uses only the Python standard library, reports descriptive statistics by replicate, uses hierarchical campaign aggregation, and writes deterministic bootstrap intervals. Raw observations are never deleted as outliers.
