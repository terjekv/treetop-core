use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_core::AttrValue;

const IAI_INNER_ITERS: usize = 2_000;

fn run_many(f: fn() -> usize) -> usize {
    let mut acc = 0usize;
    for _ in 0..IAI_INNER_ITERS {
        acc = acc.wrapping_add(f());
    }
    black_box(acc)
}

fn to_re_string() -> usize {
    let attr = AttrValue::String("web-01.example.com".to_string());
    let re = attr.to_re();
    black_box(re);
    1
}

fn to_re_set() -> usize {
    let attr = AttrValue::Set(vec![
        AttrValue::String("a".to_string()),
        AttrValue::String("b".to_string()),
        AttrValue::String("c".to_string()),
    ]);
    let re = attr.to_re();
    black_box(re);
    1
}

fn to_re_nested_set() -> usize {
    let attr = AttrValue::Set(vec![
        AttrValue::String("a".to_string()),
        AttrValue::Set(vec![AttrValue::String("b".to_string())]),
    ]);
    let re = attr.to_re();
    black_box(re);
    1
}

#[library_benchmark]
fn iai_to_re_string() -> usize {
    run_many(to_re_string)
}

#[library_benchmark]
fn iai_to_re_set() -> usize {
    run_many(to_re_set)
}

#[library_benchmark]
fn iai_to_re_nested_set() -> usize {
    run_many(to_re_nested_set)
}

library_benchmark_group!(
    name = bench_attr_value;
    benchmarks = iai_to_re_string, iai_to_re_set, iai_to_re_nested_set
);

main!(library_benchmark_groups = bench_attr_value);
