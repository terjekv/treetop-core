use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use treetop_core::bench_helpers::policy_scale::{
    CORPUS_VERSION, ScaleCorpus, allow_request, configured_policy_count, forbid_request,
    group_request, no_match_request,
};
use treetop_core::{Decision, PolicyEngine, Schema, compile_policy, compile_policy_with_schema};

fn decision_score(decision: Decision) -> usize {
    match decision {
        Decision::Allow { policies, .. } => policies.len(),
        Decision::Deny { .. } => 0,
    }
}

fn benchmark_policy_scale(c: &mut Criterion) {
    let policy_count = configured_policy_count();
    let corpus = ScaleCorpus::new(policy_count, 0);
    let replacement = ScaleCorpus::new(policy_count, 1);
    let schema: Schema = corpus
        .schema_text
        .parse()
        .expect("generated benchmark schema should parse");
    let parameter = format!("v{CORPUS_VERSION}_{policy_count}_policies");

    let mut load_group = c.benchmark_group("policy_scale_load");
    load_group.throughput(Throughput::Elements(policy_count as u64));
    load_group.bench_with_input(
        BenchmarkId::new("compile", &parameter),
        &corpus.policy_text,
        |b, policy_text| {
            b.iter(|| {
                let policies = compile_policy(black_box(policy_text.as_str()))
                    .expect("generated benchmark corpus should compile");
                black_box(policies.num_of_policies());
            });
        },
    );
    load_group.bench_with_input(
        BenchmarkId::new("compile_and_validate", &parameter),
        &corpus.policy_text,
        |b, policy_text| {
            b.iter(|| {
                let policies =
                    compile_policy_with_schema(black_box(policy_text.as_str()), black_box(&schema))
                        .expect("generated benchmark corpus should validate");
                black_box(policies.num_of_policies());
            });
        },
    );
    load_group.bench_with_input(
        BenchmarkId::new("engine", &parameter),
        &corpus.policy_text,
        |b, policy_text| {
            b.iter(|| {
                black_box(
                    PolicyEngine::new_from_str(black_box(policy_text.as_str()))
                        .expect("generated benchmark corpus should load"),
                );
            });
        },
    );
    load_group.bench_with_input(
        BenchmarkId::new("engine_with_schema", &parameter),
        &corpus.policy_text,
        |b, policy_text| {
            b.iter(|| {
                black_box(
                    PolicyEngine::new_from_str_with_schema(
                        black_box(policy_text.as_str()),
                        black_box(schema.clone()),
                    )
                    .expect("generated benchmark corpus should load with its schema"),
                );
            });
        },
    );

    let reload_engine = PolicyEngine::new_from_str_with_schema(&corpus.policy_text, schema.clone())
        .expect("initial benchmark corpus should load");
    let mut use_replacement = true;
    load_group.bench_function(BenchmarkId::new("reload_with_schema", &parameter), |b| {
        b.iter(|| {
            let policy_text = if use_replacement {
                &replacement.policy_text
            } else {
                &corpus.policy_text
            };
            reload_engine
                .reload_from_str(black_box(policy_text))
                .expect("generated benchmark corpus should reload");
            use_replacement = !use_replacement;
            black_box(reload_engine.current_version());
        });
    });
    load_group.finish();
    drop(reload_engine);

    let engine = PolicyEngine::new_from_str_with_schema(&corpus.policy_text, schema)
        .expect("evaluation benchmark corpus should load");
    let allow_request = allow_request();
    let forbid_request = forbid_request();
    let group_request = group_request();
    let no_match_request = no_match_request();

    let mut query_group = c.benchmark_group("policy_scale_query");
    query_group.throughput(Throughput::Elements(policy_count as u64));
    for (name, benchmark_request) in [
        ("evaluate_allow", &allow_request),
        ("evaluate_forbid", &forbid_request),
        ("evaluate_group", &group_request),
        ("evaluate_no_match", &no_match_request),
    ] {
        query_group.bench_function(BenchmarkId::new(name, &parameter), |b| {
            b.iter(|| {
                let decision = engine
                    .evaluate(black_box(benchmark_request))
                    .expect("benchmark request should evaluate");
                black_box(decision_score(decision));
            });
        });
    }
    query_group.bench_function(BenchmarkId::new("list_no_match", &parameter), |b| {
        b.iter(|| {
            let policies = engine
                .list_policies(black_box(&no_match_request))
                .expect("benchmark policy listing should succeed");
            black_box(policies.policies().len());
        });
    });
    query_group.bench_function(BenchmarkId::new("clone_all_policies", &parameter), |b| {
        b.iter(|| {
            let policies = engine
                .policies()
                .expect("benchmark policy cloning should succeed");
            black_box(policies.len());
        });
    });
    query_group.finish();
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(20))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = benchmark_policy_scale
}
criterion_main!(benches);
