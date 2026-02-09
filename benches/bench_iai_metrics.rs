use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::bench_helpers;

const IAI_INNER_ITERS: usize = 1_000;

#[library_benchmark]
fn iai_metrics_record_evaluation() -> u64 {
    black_box(bench_helpers::metrics_record_evaluation(IAI_INNER_ITERS))
}

#[library_benchmark]
fn iai_metrics_record_phases() -> u64 {
    black_box(bench_helpers::metrics_record_evaluation_phases(IAI_INNER_ITERS))
}

#[library_benchmark]
fn iai_metrics_record_reload() -> u64 {
    black_box(bench_helpers::metrics_record_reload(IAI_INNER_ITERS))
}

library_benchmark_group!(
    name = bench_metrics;
    benchmarks = iai_metrics_record_evaluation, iai_metrics_record_phases, iai_metrics_record_reload
);

main!(library_benchmark_groups = bench_metrics);
