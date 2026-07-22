# Policy Compiler

The stage-2 policy compiler computes a local safe set for one agent:

```text
S_i(x) = {p in C_i | A(p) >= R_i(x) and Pi_i(p, x) = 1}
```

The task-to-requirement mapper is deterministic. It starts from the policy base
requirement, evaluates every rule independently, sorts matched rule IDs
lexicographically, and joins each contribution. It reads no wall clock, host
name, process ID, random value, or external service.

No LLM controls the cryptographic decision. Policies, manifests, scenarios, and
the profile catalog are typed inputs. The compiler derives requirements,
constructs hard constraints, and asks Z3 for satisfiability over a finite
catalog domain.

## Monotone Rules

Policy rule conditions use lower-bound predicates for ordered task dimensions:
sensitivity, operational impact, confidentiality horizon, delegation depth, and
expected session duration. Network class and organization policy class are exact
membership predicates, not globally ordered dimensions.

Because rule contributions are joined into the current requirement, a matched
rule can strengthen a requirement but cannot weaken one.

## Z3 Encoding

The compiler creates one integer variable:

```text
pqtrust.policy.v1.selected_profile_index
```

The variable ranges over the canonical P0-P4 catalog indexes. Profile facts are
encoded as deterministic expressions indexed by that variable. Hard constraints
cover catalog domain membership, manifest capability support, policy allow and
deny rules, key-establishment assurance, endpoint authentication assurance and
mode restrictions, contract-evidence assurance and mode restrictions, fallback,
resumption, lease strictness, and maximum lease seconds.

Constraints are grouped under stable rejection categories and guarded by Z3
assumption labels. The compiler never uses `Optimize`, soft constraints, costs,
preferences, or resource constraints in this stage.

## Rejections

Each rejected profile reports:

- `violated_categories`: every hard-constraint category directly violated by the
  candidate.
- `irreducible_unsat_core`: a deterministic deletion-minimized subset of
  category assumptions that remains unsatisfiable for that candidate.

An irreducible core is subset-minimal with respect to the deletion procedure. It
is not claimed to be a minimum-cardinality core.

`resource_bound` is reserved for a later empirical calibration stage and is not
emitted by this compiler because catalog resource envelopes contain no measured
values.

## Validation Scope

`scripts/validate_policy_stage.py` compiles each side of each configured
scenario and records local safe sets plus their intersection. The intersection
is only a configuration sanity check. Bilateral profile selection, regret,
costs, commit-reveal, signatures, TLS handshakes, and contract signing are not
implemented in this stage.
