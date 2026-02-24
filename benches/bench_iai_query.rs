use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::bench_helpers;

const IAI_INNER_ITERS: usize = 1_000;

fn run_many(f: fn() -> usize) -> usize {
    let mut acc = 0usize;
    for _ in 0..IAI_INNER_ITERS {
        acc = acc.wrapping_add(f());
    }
    black_box(acc)
}

#[library_benchmark]
fn iai_query_user_small() -> usize {
    run_many(|| bench_helpers::query_user_with_groups(0, 0).expect("benchmark query must build"))
}

#[library_benchmark]
fn iai_query_user_medium() -> usize {
    run_many(|| bench_helpers::query_user_with_groups(20, 2).expect("benchmark query must build"))
}

#[library_benchmark]
fn iai_query_group() -> usize {
    run_many(|| bench_helpers::query_group(1).expect("benchmark query must build"))
}

#[library_benchmark]
fn iai_query_resource() -> usize {
    run_many(|| bench_helpers::query_resource(2).expect("benchmark query must build"))
}

library_benchmark_group!(
    name = bench_query;
    benchmarks = iai_query_user_small, iai_query_user_medium, iai_query_group, iai_query_resource
);

main!(library_benchmark_groups = bench_query);
