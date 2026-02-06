use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::bench_helpers;

const IAI_INNER_ITERS: usize = 1_000;

fn run_many(f: fn() -> u8) -> u64 {
    let mut acc = 0u64;
    for _ in 0..IAI_INNER_ITERS {
        acc = acc.wrapping_add(f() as u64);
    }
    black_box(acc)
}

#[library_benchmark]
fn iai_principal_eq() -> u64 {
    run_many(bench_helpers::policy_match_principal_eq)
}

#[library_benchmark]
fn iai_principal_in() -> u64 {
    run_many(bench_helpers::policy_match_principal_in)
}

#[library_benchmark]
fn iai_principal_any() -> u64 {
    run_many(bench_helpers::policy_match_principal_any)
}

#[library_benchmark]
fn iai_principal_is_in() -> u64 {
    run_many(bench_helpers::policy_match_principal_is_in)
}

#[library_benchmark]
fn iai_resource_eq() -> u64 {
    run_many(bench_helpers::policy_match_resource_eq)
}

#[library_benchmark]
fn iai_resource_any() -> u64 {
    run_many(bench_helpers::policy_match_resource_any)
}

#[library_benchmark]
fn iai_resource_is_in() -> u64 {
    run_many(bench_helpers::policy_match_resource_is_in)
}

library_benchmark_group!(
    name = bench_policy_match;
    benchmarks = iai_principal_eq, iai_principal_in, iai_principal_any, iai_principal_is_in,
        iai_resource_eq, iai_resource_any, iai_resource_is_in
);

main!(library_benchmark_groups = bench_policy_match);
