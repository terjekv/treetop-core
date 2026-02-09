use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::{action_entity_uid, group_entity_uid, resource_entity_uid, user_entity_uid};

const IAI_INNER_ITERS: usize = 2_000;

fn run_many(f: fn() -> usize) -> usize {
    let mut acc = 0usize;
    for _ in 0..IAI_INNER_ITERS {
        acc = acc.wrapping_add(f());
    }
    black_box(acc)
}

fn user_uid_no_ns() -> usize {
    user_entity_uid("alice", &[])
        .expect("benchmark uid must build")
        .to_string()
        .len()
}

fn user_uid_with_ns() -> usize {
    user_entity_uid("alice", &["Ns1", "Ns2"])
        .expect("benchmark uid must build")
        .to_string()
        .len()
}

fn group_uid_no_ns() -> usize {
    group_entity_uid("admins", &[])
        .expect("benchmark uid must build")
        .to_string()
        .len()
}

fn action_uid_with_ns() -> usize {
    action_entity_uid("view_host", &["Ns1", "Ns2", "Ns3"])
        .expect("benchmark uid must build")
        .to_string()
        .len()
}

fn resource_uid() -> usize {
    resource_entity_uid("Host", "web-01.example.com")
        .expect("benchmark uid must build")
        .to_string()
        .len()
}

#[library_benchmark]
fn iai_user_uid_no_ns() -> usize {
    run_many(user_uid_no_ns)
}

#[library_benchmark]
fn iai_user_uid_with_ns() -> usize {
    run_many(user_uid_with_ns)
}

#[library_benchmark]
fn iai_group_uid_no_ns() -> usize {
    run_many(group_uid_no_ns)
}

#[library_benchmark]
fn iai_action_uid_with_ns() -> usize {
    run_many(action_uid_with_ns)
}

#[library_benchmark]
fn iai_resource_uid() -> usize {
    run_many(resource_uid)
}

library_benchmark_group!(
    name = bench_entity_uid;
    benchmarks = iai_user_uid_no_ns, iai_user_uid_with_ns, iai_group_uid_no_ns, iai_action_uid_with_ns, iai_resource_uid
);

main!(library_benchmark_groups = bench_entity_uid);
