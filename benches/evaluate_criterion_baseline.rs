mod evaluate_common;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use evaluate_common::{build_scenario, wide_matrix_specs_baseline};
use std::hint::black_box;
use treetop_core::Decision;

fn score(decision: Decision) -> usize {
    match decision {
        Decision::Allow { policies, .. } => policies.len(),
        Decision::Deny { .. } => 0,
    }
}

fn benchmark_evaluate_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate_baseline");
    group.sample_size(40);

    let scenarios: Vec<_> = wide_matrix_specs_baseline()
        .into_iter()
        .map(build_scenario)
        .collect();

    for scenario in &scenarios {
        group.bench_with_input(BenchmarkId::from_parameter(scenario.name), scenario, |b, s| {
            b.iter(|| {
                let decision = s
                    .engine
                    .evaluate(black_box(&s.request))
                    .expect("benchmark requests are valid");
                black_box(score(decision));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_evaluate_baseline);
criterion_main!(benches);
