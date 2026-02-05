mod evaluate_common;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use evaluate_common::{build_scenario, wide_matrix_specs_labels};
use std::hint::black_box;
use treetop_core::Decision;

fn score(decision: Decision) -> usize {
    match decision {
        Decision::Allow { policies, .. } => policies.len(),
        Decision::Deny { .. } => 0,
    }
}

fn benchmark_evaluate_labels(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate_labels");
    group.sample_size(40);

    let scenarios: Vec<_> = wide_matrix_specs_labels()
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

criterion_group!(benches, benchmark_evaluate_labels);
criterion_main!(benches);
