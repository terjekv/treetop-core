mod evaluate_common;

use evaluate_common::{build_scenario, iai_matrix_specs_groups, Scenario};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::sync::LazyLock;
use treetop_core::Decision;

const IAI_INNER_ITERS: usize = 1_000;

fn score(decision: Decision) -> usize {
    match decision {
        Decision::Allow { policies, .. } => policies.len(),
        Decision::Deny { .. } => 0,
    }
}

fn run_many(scenario: &Scenario) -> usize {
    let mut acc = 0usize;
    for _ in 0..IAI_INNER_ITERS {
        let decision = scenario
            .engine
            .evaluate(black_box(&scenario.request))
            .expect("benchmark requests are valid");
        acc = acc.wrapping_add(black_box(score(decision)));
    }
    acc
}

static SCENARIOS: LazyLock<Vec<Scenario>> = LazyLock::new(|| {
    iai_matrix_specs_groups()
        .into_iter()
        .map(build_scenario)
        .collect::<Vec<_>>()
});

#[library_benchmark]
fn iai_groups_40() -> usize {
    run_many(&SCENARIOS[0])
}

library_benchmark_group!(name = evaluate_groups; benchmarks = iai_groups_40);

main!(library_benchmark_groups = evaluate_groups);
