# Commit-Reveal And Contracts

Stage 5 binds bilateral selector inputs and the selected result into a
verifiable transcript, then binds the transcript into an unsigned trust contract
that both agents sign independently.

## Threat Model

Commit-reveal prevents one party from waiting to see the other party's
selection inputs and then adapting its own declared safe set, preference hash,
manifest hash, policy-compilation hash, or evidence hash. Each party first
publishes only a SHA-256 commitment over its canonical proposal bytes and a
caller-supplied 32-byte nonce. Reveals are accepted only after both commitments
exist.

This layer does not implement network transport, endpoint channel binding,
distributed replay storage, active network attack campaigns, or final A2A
integration.

## Phase Ordering

The local protocol session enforces both commitments before reveal, checks that
each reveal matches the earlier commitment, requires matching public scenario
and evidence hashes, requires distinct roles and agents, rejects expired
proposals, and delegates session/commitment replay checks to the local replay
registry. Proposal validation, reveal acceptance, transcript verification,
contract verification, contract activation, replay registration, and replay
cleanup all receive an explicit caller-supplied UTC time. Core protocol logic
does not read the wall clock.

## Time Semantics

Protocol datetimes are timezone-aware UTC values. Naive datetimes are rejected.
Contract leases are inclusive at `issued_at` and exclusive at `expires_at`:
`issued_at <= activation_time < expires_at`. Activation before `issued_at`,
activation exactly at `expires_at`, and activation after `expires_at` fail
closed. Production adapters may obtain the current UTC time and pass it
explicitly; deterministic laboratory validation injects fixture times inside
the historical lease interval.

## Nonces

Production nonces must come from `secrets.token_bytes(32)` through the protocol
helper. Deterministic laboratory scripts may inject explicit 32-byte fixture
nonces to make transcripts byte-reproducible, and such artifacts are labeled as
laboratory fixtures. Production nonces are never derived from public protocol
inputs.

## Transcript Binding

`NegotiationTranscript` records both commitments, both reveals, both local safe
sets, the recomputed common-safe set, Pareto frontier, selected profile, and
selection hash. Verification recomputes commitments, proposal hashes,
common-safe intersection, selected profile fields from the selector result, and
the transcript hash. A serialized selected profile is not trusted by itself.

## Dual Signatures

`UnsignedTrustContract` copies scenario, task, catalog, evidence, manifest,
policy, preference, transcript, selection, and selected profile fields into one
canonical payload. Both agents sign exactly the same canonical bytes.

The selected profile determines the ML-DSA contract-evidence algorithm:

- `mldsa65` requires `ML-DSA-65`;
- `mldsa87` requires `ML-DSA-87`.

The canonical public evidence-algorithm names are exactly `ML-DSA-65` and
`ML-DSA-87`. Any OpenSSL or filename-specific spelling is normalized only at
the manifest/parser boundary; unsupported values fail closed instead of being
silently mapped.

The public agent evidence-key manifest contains metadata only: agent ID,
canonical algorithm, key ID, public-key SHA-256, and repository-relative public
key path. The laboratory signer resolves the sibling private key from the
validated local `.local/pqtrust-crypto/agents/<agent>/` layout, verifies private
file permissions, checks that the private/public pair matches, and never places
private-key paths or bytes in signed contract artifacts.

The required inventory is ten entries: both `ML-DSA-65` and `ML-DSA-87` for
`cloud-orchestrator`, `public-tool-agent`, `enterprise-api-agent`,
`edge-control-agent`, and `quantum-ready-tool-agent`. Run
`python3 scripts/validate_agent_evidence_keys.py` before signed-contract
validation to write `artifacts/protocol/agent_evidence_key_validation.json`.

Verification rejects the wrong parameter set, wrong signing agent, wrong role,
wrong key ID, wrong public-key fingerprint, missing signatures, invalid
signatures, lease violations, transcript mismatches, and selected profiles that
are not in both revealed local safe sets.

Endpoint TLS authentication remains classical in the current profile catalog.
ML-DSA signatures are application-level contract evidence and are not a claim of
post-quantum endpoint authentication.

## Replay Protection

The replay abstraction stores session IDs, commitment hashes, transcript hashes,
contract IDs, signed-contract hashes, and expiries. The in-memory implementation
is for tests; the JSON-file implementation performs atomic single-host
laboratory updates. This is not a distributed database. Replay operations use
the supplied reference time for expiry cleanup and duplicate-active-contract
checks, so historical fixtures can be validated reproducibly when the supplied
activation time is inside the lease. Expired entries are never treated as active
relative to that supplied time.

## Limitations

Stage 5 does not add network services, final transport binding, tc/netem,
attacks, campaigns, figures, or paper text. It does not modify raw calibration
evidence or paired measured-cost evidence.
## Failure Transcript And Abort

For infeasible negotiations, the completed commit-reveal exchange is bound into
a negotiation failure transcript. Verification recomputes commitments,
proposal hashes, local safe sets, bilateral infeasibility, the conflict
certificate hash, and the transcript hash.

An infeasible session produces a safe abort record instead of a trust contract.
The abort record requires `fallback_attempted: false`, `selected_profile_id:
null`, and `contract_created: false`. Any later attempt to attach a selected
profile, contract, resumption, activation, or fallback is rejected.

The explanation and remediation layers are separate. A conflict certificate can
explain why hard constraints cannot be jointly satisfied; remediation reports
are informational and must not silently downgrade endpoint authentication,
assurance floors, explicit downgrade prohibitions, or other hard security
requirements.
# Stage 7 Contract Binding

Stage 7 treats Stage 5 signed contracts as the authority for execution. TLS
activation is blocked until the contract verifies, both signatures verify, the
activation time is inside the contract lease, selected profile membership is
confirmed in both revealed safe sets, transcript and selection hashes match, and
the profile properties match the catalog.
