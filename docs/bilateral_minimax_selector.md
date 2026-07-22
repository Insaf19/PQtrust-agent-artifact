# Bilateral Minimax Selector

Stage 4B adds deterministic measured-cost selection after hard policy
compilation. It is not a reinforcement-learning stage and it does not relax
security constraints.

## Hard Constraints First

Each side compiles its local hard-safe set with the existing Z3 policy
compiler. The selector only sees the bilateral intersection of those safe
sets. Unsafe profiles are never assigned an eligible selector cost, and an
empty common-safe set is a validation failure reserved for a later conflict
certificate stage.

## Measured TLS Cost Vector

For each profile P0-P4, the selector uses exactly three calibrated relative TLS
dimensions from `selector_tls_cost_evidence.json`:

- paired wall-time relative estimate;
- paired process-CPU-time relative estimate;
- paired total-handshake-byte relative estimate.

P0 is the calibration reference, not an automatic winner. Energy, peak memory,
ML-DSA contract cost, security level, fallback policy, lease policy, and
compatibility penalties are not selector costs in this stage.

## Fixed Global Normalization

Each metric is normalized over the complete validated P0-P4 catalog:

```text
(m(p) - global_min_m) / (global_max_m - global_min_m)
```

The anchors are computed once from the complete cost evidence, not from each
scenario safe set. This keeps a profile's normalized cost from changing merely
because a different profile is absent from a scenario.

## Preferences

Agent cost preferences are explicit negotiation parameters, not measurements.
They use integer basis points and must sum to 10000. The registered preferences
live under `configs/preferences/` and are hashed with domain
`PQTrust.AgentCostPreference.v1`.

## Pareto Filtering

Pareto filtering compares only the raw measured TLS cost vector inside the
bilateral common-safe set. Profile `p` dominates `q` when every measured cost
dimension of `p` is less than or equal to `q`, and at least one is strictly
lower. Security assurance is not part of this cost relation because security
has already been enforced as a hard constraint.

When the frontier contains one profile, selection is valid but reported as
frontier collapse rather than a meaningful fairness trade-off. Reports use
three structural selection modes:

- `singleton_common_safe_set`: exactly one bilateral common-safe profile exists.
- `pareto_frontier_collapse`: multiple common-safe profiles exist, but measured
  Pareto filtering leaves one candidate.
- `bilateral_minimax_regret`: at least two Pareto-frontier profiles remain, so
  minimax regret is actually exercised.

The original three scientific scenarios legitimately collapse under the
current hard-safe sets and measured TLS evidence. `critical-edge-command` has a
single common-safe profile. `low-risk-public-tool` and
`sensitive-enterprise-api` have multiple common-safe profiles but one measured
cost-dominant Pareto candidate. These results validate safety filtering and
dominance evidence, but they do not prove bilateral fairness.

## Regret And Minimax Objective

For each agent `i` and profile `p`, the selector computes:

```text
C_i(p) = w_wall_i * norm_wall(p)
       + w_cpu_i * norm_cpu(p)
       + w_bytes_i * norm_bytes(p)
```

Regret is:

```text
regret_i(p) = C_i(p) - min_q C_i(q)
```

where `q` ranges over the same Pareto-safe candidate set. The selected profile
minimizes, in order:

1. maximum bilateral regret;
2. total bilateral regret;
3. maximum normalized measured cost component;
4. total normalized measured cost;
5. canonical profile ID.

No randomness and no unilateral tie-breaks are used.

## Decimal Evidence

Selector evidence is loaded with `Decimal` JSON parsing. Calibrated ratios,
confidence bounds, normalized values, weighted costs, regrets, and tie-break
values remain Decimal values. Canonical selector reports serialize Decimals as
normalized decimal strings; rounded six-decimal display values can be added for
public reporting, but display values are not decision inputs.

## Sensitivity Analyses

Uncertainty sensitivity recomputes selection under deterministic cost corners
represented by the paired bootstrap intervals: point estimates, all lower
bounds, all upper bounds, and one-timing-metric lower/upper combinations.

Weight sensitivity evaluates all integer basis-point triples in increments of
1000 for both agents. It records selected-profile frequencies and classifies
the scenario as frontier collapse, preference-robust selection, or
preference-sensitive selection.

Sensitivity outputs do not modify the primary point-estimate result.
Structural collapse is not labeled as preference or uncertainty robustness.
Only a non-singleton Pareto frontier may be classified as preference-robust,
preference-sensitive, uncertainty-robust, or uncertainty-sensitive.

Stage 5 transcript verification treats the selector output as something to
recompute and bind, not as a serialized decision to trust blindly.

## Capability Ablation

Stage 4B adds `low-risk-quantum-ready-tool`, a controlled selector stress test
using the same public, observation-only, short-horizon task as the original
low-risk scenario. The responder supports `P0`, `P1`, and `P3` and has an
explicit bandwidth-conscious policy preference. This is a capability ablation,
not a claim about naturally occurring production frequency.

No cost values are injected. The ablation reuses the checksum-verified paired
relative TLS evidence. Under that evidence, `P1` is dominated, while `P0` and
`P3` form a real measured trade-off: `P3` has lower wall-time and process-CPU
ratios, and `P0` has substantially lower handshake-byte ratio.

## Preference-Conflict Evaluation

For the non-degenerate ablation, Stage 4B evaluates the complete deterministic
integer basis-point grid with increment 1000: 66 preference triples per agent
and 4356 joint pairs. For each pair it records each side's unilateral optimum,
whether those optima conflict, the bilateral minimax-regret selection, and
safe same-frontier baselines. The analysis is exhaustive policy-space
enumeration, not random sampling and not statistical superiority.

For each conflict pair and baseline:

```text
fairness_gain = baseline_maximum_regret - minimax_maximum_regret
```

Negative fairness gain is a validation failure. The analysis is limited to the
registered cost dimensions and policy weights; it does not establish broader
deployment fairness outside the modeled preference space.

## Timing Caveat

The quality gate preserves that absolute timing stability failed for the
source campaigns. Selector usability is based on raw integrity, scientific
compatibility, complete paired TLS blocks, and paired relative timing stability
passing for P0-P4. Reports must keep both facts visible.

## Current Limitations

The selector currently has no memory metric, no energy metric, and no measured
canonical-contract ML-DSA cost. Those remain separate future measurements.
