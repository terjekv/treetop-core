# Performance Benchmarks

This project includes two benchmark systems for the `PolicyEngine::evaluate()` hot path:

- **Criterion** for wall-clock latency/throughput trends
- **iai-callgrind** for instruction-level deterministic regression detection

Both are configured with a scenario matrix that stresses key dimensions:

- policy-set size (small/medium/large)
- allow vs deny paths
- group cardinality
- label-registry complexity
- namespace depth
- observability enabled/disabled

## Bench Files

- `benches/evaluate_common.rs` - shared scenario matrix + fixture builder
- `benches/evaluate_criterion.rs` - Criterion benchmark entrypoint
- `benches/evaluate_iai.rs` - iai-callgrind benchmark entrypoint

## Run Locally

### Criterion (default features)

```bash
cargo bench --bench evaluate_criterion -- --noplot
```

### Criterion (observability enabled)

```bash
cargo bench --bench evaluate_criterion --features observability -- --noplot
```

### iai-callgrind (default features)

Requires:

- `valgrind`
- `iai-callgrind-runner` (install with `cargo install --locked iai-callgrind-runner`)

> Note: `iai-callgrind-runner` is Linux only because it depends on Valgrind/Callgrind.

```bash
cargo bench --bench evaluate_iai
```

### iai-callgrind (observability enabled)

```bash
cargo bench --bench evaluate_iai --features observability
```

### Recommended local workflow by platform

- **macOS:** Run Criterion locally (`cargo bench --bench evaluate_criterion ...`) and use CI for `iai-callgrind`.
- **Linux:** Run both Criterion and `iai-callgrind` locally.

## Criterion Regression Compare

Use the helper script to compare two Criterion result directories:

```bash
python3 scripts/perf/compare_criterion.py <base_target_dir> <head_target_dir> <max_regression_pct>
```

Example:

```bash
python3 scripts/perf/compare_criterion.py /tmp/criterion-base-no-obs /tmp/criterion-head-no-obs 8
```

The script exits non-zero if any scenario regresses more than the threshold.

## CI Layout

Workflow: `.github/workflows/perf.yml`

- **criterion-regression** (gating):
  - checks out base commit in a worktree
  - runs `evaluate_criterion` on base and head
  - compares means using `scripts/perf/compare_criterion.py`
  - fails if any scenario exceeds `PERF_MAX_REGRESSION_PCT` (default `8`)
- **iai-callgrind-regression**:
  - runs base as saved baseline (`--save-baseline base`)
  - runs head against that baseline (`--baseline base`)
  - executes with observability on/off matrix
  - posts a PR comment with a short summary and output tail for each matrix variant

## Recommended Repo Workflow

- Protect `main` and require pull requests for changes.
- Require Perf workflow checks to pass before merge.
- Use PR-to-`main` as the primary performance regression gate.
- Keep direct pushes to `main` disabled except for maintainers/emergency flow.

## Tuning Guidance

- Start with a looser threshold (for example 8-10%) and tighten after a few weeks of data.
- Prefer adding new scenarios only when they map to real production-like request shapes.
- Keep matrix entries stable to preserve trend comparability over time.
