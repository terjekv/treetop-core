# Performance Benchmarks

This project uses two complementary benchmark systems:

- **Criterion** for wall-clock latency and throughput trends.
- **Gungraun** with Valgrind/Callgrind for deterministic instruction-level
  regression detection.

The evaluation benchmarks use a scenario matrix that varies policy-set size,
allow and deny paths, group cardinality, label-registry complexity, namespace
depth, and whether observability is enabled.

The separate policy-scale suite deterministically generates mixed permit and
forbid corpora without checking a large generated file into the repository. Pull
requests exercise 10,000 policies as a correctness smoke test. Scheduled and
manual scale runs default to 100,000 policies and cover parsing, strict schema
validation, snapshot construction, reloads, evaluation, policy listing, cloning,
and peak resident memory.

## Bench Files

- `benches/evaluate_common.rs` contains the shared scenario matrix and fixture
  builder.
- `benches/evaluate_criterion_*.rs` contains the Criterion evaluation slices.
- `benches/evaluate_iai_*.rs` contains the Gungraun evaluation slices.
- `benches/bench_iai_*.rs` contains focused Gungraun benchmarks for internal hot
  paths.
- `benches/policy_scale_common.rs` generates deterministic scale corpora shared
  by the integration test and Criterion benchmark.
- `benches/policy_scale_criterion.rs` measures 100k+ policy operations outside
  Callgrind.

`bench_iai_metrics` retains the historical focused sink-dispatch cases.
`bench_iai_metrics_evaluation` exercises complete evaluations with a disabled
sink, the legacy owned-payload adapter, and an allocation-conscious borrowed sink.
Keeping the complete-evaluation cases in their own target preserves the historical
dispatch-target aggregate while distinguishing Core evaluation work from metrics
payload construction.

`bench_iai_entity_uid` covers both one-shot API helper construction and repeated
identity access on one typed request. `bench_iai_timers` keeps enabled timing
overhead separate from the disabled path used when neither metrics nor debug
tracing consumes evaluation phase measurements.

The `iai` target names are retained intentionally. Version 3 of the reusable
workflow uses those stable names to compare a Gungraun head revision with an
IAI-Callgrind base revision and preserve benchmark history.

## Run Locally

### Criterion

Run a default-feature evaluation slice:

```bash
cargo bench --bench evaluate_criterion_baseline -- --noplot
```

Run the same slice with observability enabled:

```bash
cargo bench --bench evaluate_criterion_baseline \
  --features observability -- --noplot
```

Replace `baseline` with `groups`, `labels`, or `namespaced` for the other
evaluation slices.

Run the 100,000-policy scale correctness test and benchmark:

```bash
TREETOP_SCALE_POLICY_COUNT=100000 \
  cargo test --release --all-features --test policy_scale \
  configured_policy_scale_loads_evaluates_lists_and_reloads \
  -- --ignored --exact --nocapture
TREETOP_SCALE_POLICY_COUNT=100000 \
  cargo bench --bench policy_scale_criterion -- --noplot
```

Set `TREETOP_SCALE_POLICY_COUNT` to another value, such as `250000`, to probe a
different supported scale. The default is 100,000 when the variable is absent.

### Gungraun

Gungraun requires Linux, Valgrind, and the runner version matching the crate:

```bash
cargo install --locked gungraun-runner --version 0.19.4
cargo bench --bench evaluate_iai_baseline
```

Run an internal hot-path target with the required feature:

```bash
cargo bench --bench bench_iai_query --features bench-internal
```

Add `observability` to measure the enabled path:

```bash
cargo bench --bench bench_iai_metrics_evaluation \
  --features bench-internal,observability
```

On macOS, run Criterion locally and use Linux CI for Gungraun/Callgrind.

## Criterion Regression Compare

The local helper compares two Criterion result directories:

```bash
python3 scripts/perf/compare_criterion.py \
  <base_target_dir> <head_target_dir> <max_regression_pct>
```

It exits non-zero when a scenario exceeds the supplied threshold.

## CI Layout

`.github/workflows/perf.yml` calls the reviewed v3 reusable workflow at an
immutable commit and runs both backends against the pull request base and head.
It uses these feature sets:

- `no-obs`: `bench-internal`
- `obs`: `bench-internal,observability`

Gungraun regressions above 8% and Criterion median regressions above 10% fail
the check. The workflow publishes one sticky pull-request report, so its token
has `contents: read` and `pull-requests: write` permissions only.

`.github/workflows/policy-scale.yml` runs weekly and on manual dispatch. It
executes the ignored correctness test under `/usr/bin/time -v` so the log records
peak RSS, then runs the Criterion scale target. The workflow accepts a
`policy_count` input and defaults to 100,000. This target is intentionally absent
from the pull-request Callgrind matrix because instrumentation cost grows with
the generated corpus.

## Maintenance Guidance

- Keep benchmark entries synchronized across `Cargo.toml`, `benches/`, and the
  performance workflow.
- Keep scenario and target names stable to preserve base/head and historical
  comparisons.
- Add scenarios only when they represent a production-relevant request shape.
- Tune thresholds from observed CI noise; treat Criterion as the noisier signal.
