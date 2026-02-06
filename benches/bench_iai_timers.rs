use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::bench_helpers;

const IAI_INNER_ITERS: usize = 10_000;

#[library_benchmark]
fn iai_phase_timer_overhead() -> u128 {
    black_box(bench_helpers::phase_timer_overhead(IAI_INNER_ITERS))
}

library_benchmark_group!(
    name = bench_timers;
    benchmarks = iai_phase_timer_overhead
);

main!(library_benchmark_groups = bench_timers);
