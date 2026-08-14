use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::bench_helpers;

const EVALUATION_INNER_ITERS: usize = 128;

#[library_benchmark]
fn iai_metrics_evaluate_disabled() -> u64 {
    black_box(bench_helpers::metrics_evaluate_disabled(
        EVALUATION_INNER_ITERS,
    ))
}

#[library_benchmark]
fn iai_metrics_evaluate_legacy() -> u64 {
    black_box(bench_helpers::metrics_evaluate_legacy(
        EVALUATION_INNER_ITERS,
    ))
}

#[library_benchmark]
fn iai_metrics_evaluate_borrowed() -> u64 {
    black_box(bench_helpers::metrics_evaluate_borrowed(
        EVALUATION_INNER_ITERS,
    ))
}

library_benchmark_group!(
    name = bench_metrics_evaluation;
    benchmarks = iai_metrics_evaluate_disabled,
        iai_metrics_evaluate_legacy,
        iai_metrics_evaluate_borrowed
);

main!(library_benchmark_groups = bench_metrics_evaluation);
