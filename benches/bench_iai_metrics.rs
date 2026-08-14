use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::bench_helpers;

const IAI_INNER_ITERS: usize = 1_000;
const EVALUATION_INNER_ITERS: usize = 128;

#[library_benchmark]
fn iai_metrics_record_evaluation() -> u64 {
    black_box(bench_helpers::metrics_record_evaluation(IAI_INNER_ITERS))
}

#[library_benchmark]
fn iai_metrics_record_phases() -> u64 {
    black_box(bench_helpers::metrics_record_evaluation_phases(
        IAI_INNER_ITERS,
    ))
}

#[library_benchmark]
fn iai_metrics_record_reload() -> u64 {
    black_box(bench_helpers::metrics_record_reload(IAI_INNER_ITERS))
}

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
    name = bench_metrics;
    benchmarks = iai_metrics_record_evaluation,
        iai_metrics_record_phases,
        iai_metrics_record_reload,
        iai_metrics_evaluate_disabled,
        iai_metrics_evaluate_legacy,
        iai_metrics_evaluate_borrowed
);

main!(library_benchmark_groups = bench_metrics);
