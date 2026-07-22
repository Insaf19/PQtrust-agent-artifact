"""Deterministic hierarchical bootstrap for calibration campaigns."""

from __future__ import annotations

import random
from collections.abc import Sequence

from pqtrust_agent.metrics.descriptive import median, quantile

BOOTSTRAP_SEED = 20260801
BOOTSTRAP_ITERATIONS = 10_000


def hierarchical_bootstrap_median_ci(
    replicate_values: Sequence[Sequence[float]],
    *,
    iterations: int = BOOTSTRAP_ITERATIONS,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, float | int]:
    if not replicate_values:
        raise ValueError("at least one replicate is required")
    if any(len(rep) == 0 for rep in replicate_values):
        raise ValueError("replicates must not be empty")
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    rng = random.Random(seed)
    bootstrapped: list[float] = []
    replicates = [list(map(float, replicate)) for replicate in replicate_values]
    for _ in range(iterations):
        sampled_medians: list[float] = []
        for _slot in range(len(replicates)):
            replicate = rng.choice(replicates)
            resampled = [rng.choice(replicate) for _item in range(len(replicate))]
            sampled_medians.append(median(resampled))
        bootstrapped.append(median(sampled_medians))
    return {
        "seed": seed,
        "iterations": iterations,
        "confidence_level": 0.95,
        "lower": quantile(bootstrapped, 0.025),
        "upper": quantile(bootstrapped, 0.975),
    }
