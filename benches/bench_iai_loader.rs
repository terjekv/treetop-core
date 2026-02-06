use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::sync::LazyLock;
use treetop_core::bench_helpers;
use treetop_core::compile_policy;

fn build_policy_text(count: usize) -> String {
    let mut text = String::new();
    text.push_str(
        "permit (principal == User::\"alice\", action == Action::\"view_host\", resource is Host);\n",
    );
    for idx in 0..count {
        text.push_str(&format!(
            "permit (principal == User::\"noise_{idx}\", action == Action::\"action_{idx}\", resource is Host);\n",
        ));
    }
    text
}

static POLICY_TEXT_SMALL: LazyLock<String> = LazyLock::new(|| build_policy_text(8));
static POLICY_TEXT_MEDIUM: LazyLock<String> = LazyLock::new(|| build_policy_text(80));

static POLICY_SET_MEDIUM: LazyLock<cedar_policy::PolicySet> = LazyLock::new(|| {
    compile_policy(POLICY_TEXT_MEDIUM.as_str()).expect("benchmark policy must compile")
});

#[library_benchmark]
fn iai_compile_policy_small() -> usize {
    let set = compile_policy(black_box(POLICY_TEXT_SMALL.as_str()))
        .expect("benchmark policy must compile");
    black_box(set.num_of_policies())
}

#[library_benchmark]
fn iai_compile_policy_medium() -> usize {
    let set = compile_policy(black_box(POLICY_TEXT_MEDIUM.as_str()))
        .expect("benchmark policy must compile");
    black_box(set.num_of_policies())
}

#[library_benchmark]
fn iai_precompute_permit_policies_medium() -> usize {
    bench_helpers::precompute_permit_policies_len(&POLICY_SET_MEDIUM)
}

library_benchmark_group!(
    name = bench_loader;
    benchmarks = iai_compile_policy_small, iai_compile_policy_medium, iai_precompute_permit_policies_medium
);

main!(library_benchmark_groups = bench_loader);
