# Stage 9 Statistical Analysis And Figures

Stage 9 is the repository-registered analysis layer for the validated Stage 8
final campaign. It does not rerun the campaign, change policy or selection
algorithms, modify raw JSONL, or edit the paper.

The registered plan is `configs/analysis/stage9_analysis_plan.yaml`. It records
the Stage 8 run ID, raw manifest hash, derived-artifact hash, primary and
secondary outcomes, paired comparison unit, bootstrap seed, 95% confidence
level, Holm correction, outlier and missing-value policies, figure inventory,
table inventory, and the explicit prohibition on post-hoc metric substitution.
It is repository-registered only; it is not claimed as an external
preregistration.

## Commands

```bash
python3 scripts/register_stage9_analysis.py
python3 scripts/run_stage9_analysis.py
python3 scripts/generate_stage9_figures.py
python3 scripts/generate_stage9_tables.py
python3 scripts/validate_stage9.py
```

Use `--replace-existing` only when intentionally replacing an existing
validated analysis bundle.

## Design

Feasible-session method comparisons are paired by scenario, block, and
repetition. The analysis uses the registered Stage 8 method schedule and does
not treat repeated methods or component batches as independent samples for
unrelated questions.

Normality is not assumed. Descriptive summaries report robust quantiles and
standard summaries. Paired continuous effects report paired median difference,
paired mean difference, relative percentage difference, percentile bootstrap
95% intervals, a paired standardized effect size, and Holm-corrected
two-sided sign-test p-values where a formal test is appropriate.

Valid slow observations are retained. Missing unavailable measurements are
reported as unavailable and are not imputed or replaced with post-hoc metrics.

## Evidence Boundaries

Selector fairness claims are split into deterministic exhaustive
preference-grid evidence from Stage 4B and measured runtime evidence from
Stage 8. Runtime repetitions do not create new preference samples.

Infeasible and adversarial safety summaries report exact confidence bounds for
zero observed violations or 200/200 rejections, but the claim ledger prohibits
stronger wording such as zero true probability or universal security.

## Figures And Tables

Figures are generated under `artifacts/analysis/figures/` as PDF, SVG, and
300 dpi PNG. Every plotted mark is backed by
`artifacts/analysis/figure_data/<figure-id>/`, containing data, metadata,
caption, provenance, and checksums.

Tables are generated under `artifacts/analysis/tables/` as CSV, LaTeX
fragments, and JSON provenance. Significant digits are compact and avoid
invented precision.

The visual design uses matplotlib directly, a colorblind-accessible palette,
consistent method colors, panel labels, vector text, concise captions, and no
3D effects, gradients, decorative icons, or truncated axes that exaggerate
effects.

## Limitations

The Stage 8 final run is a single-machine local laboratory campaign. Its
results support implementation validation and measured local performance, not
Internet-scale deployment claims. The registered adversarial suite validates
the tested attacks only.
