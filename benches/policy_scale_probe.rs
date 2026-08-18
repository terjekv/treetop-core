use std::hint::black_box;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::fs;

use treetop_core::bench_helpers::policy_scale::{
    CORPUS_VERSION, ScaleCorpus, allow_request, configured_policy_count, forbid_request,
    group_request, no_match_request,
};
use treetop_core::{PolicyEngine, Schema};

const PROBE_SAMPLES_ENV: &str = "TREETOP_SCALE_PROBE_SAMPLES";
const DEFAULT_PROBE_SAMPLES: usize = 25;

#[derive(Clone, Copy)]
struct MemorySnapshot {
    resident_kib: Option<u64>,
    peak_kib: Option<u64>,
}

struct LatencyStats {
    median: Duration,
    p95: Duration,
}

fn configured_probe_samples() -> usize {
    match std::env::var(PROBE_SAMPLES_ENV) {
        Ok(raw) => {
            let samples = raw.parse::<usize>().unwrap_or_else(|error| {
                panic!("{PROBE_SAMPLES_ENV} must be a positive integer, got {raw:?}: {error}")
            });
            assert!(samples > 0, "{PROBE_SAMPLES_ENV} must be greater than zero");
            samples
        }
        Err(std::env::VarError::NotPresent) => DEFAULT_PROBE_SAMPLES,
        Err(error) => panic!("failed to read {PROBE_SAMPLES_ENV}: {error}"),
    }
}

fn measure_latency(mut operation: impl FnMut(), samples: usize) -> LatencyStats {
    operation();

    let mut elapsed = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        operation();
        elapsed.push(started.elapsed());
    }
    elapsed.sort_unstable();

    let median = elapsed[elapsed.len() / 2];
    let p95_index = (elapsed.len() * 95).div_ceil(100).saturating_sub(1);
    LatencyStats {
        median,
        p95: elapsed[p95_index],
    }
}

#[cfg(target_os = "linux")]
fn memory_snapshot() -> MemorySnapshot {
    let status = fs::read_to_string("/proc/self/status").ok();
    MemorySnapshot {
        resident_kib: status
            .as_deref()
            .and_then(|contents| status_value_kib(contents, "VmRSS:")),
        peak_kib: status
            .as_deref()
            .and_then(|contents| status_value_kib(contents, "VmHWM:")),
    }
}

#[cfg(not(target_os = "linux"))]
fn memory_snapshot() -> MemorySnapshot {
    MemorySnapshot {
        resident_kib: None,
        peak_kib: None,
    }
}

#[cfg(target_os = "linux")]
fn status_value_kib(status: &str, field: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        line.strip_prefix(field)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn format_duration(duration: Duration) -> String {
    if duration >= Duration::from_secs(1) {
        format!("{:.3} s", duration.as_secs_f64())
    } else {
        format!("{:.3} ms", duration.as_secs_f64() * 1_000.0)
    }
}

fn format_mib(value_kib: Option<u64>) -> String {
    value_kib.map_or_else(
        || "unavailable".to_string(),
        |value| format!("{:.1}", value as f64 / 1_024.0),
    )
}

fn format_delta_mib(after_kib: Option<u64>, before_kib: Option<u64>) -> String {
    match (after_kib, before_kib) {
        (Some(after), Some(before)) => {
            format!("{:.1}", after.saturating_sub(before) as f64 / 1_024.0)
        }
        _ => "unavailable".to_string(),
    }
}

fn print_latency_row(name: &str, stats: &LatencyStats) {
    println!(
        "| {name} | {} | {} |",
        format_duration(stats.median),
        format_duration(stats.p95)
    );
}

fn main() {
    let policy_count = configured_policy_count();
    let samples = configured_probe_samples();
    let process_start_memory = memory_snapshot();

    let generate_started = Instant::now();
    let corpus = ScaleCorpus::new(policy_count, 0);
    let replacement = ScaleCorpus::new(policy_count, 1);
    let generate_elapsed = generate_started.elapsed();
    let generated_memory = memory_snapshot();

    let schema_started = Instant::now();
    let schema: Schema = corpus
        .schema_text
        .parse()
        .expect("generated probe schema should parse");
    let schema_elapsed = schema_started.elapsed();

    let load_started = Instant::now();
    let engine = PolicyEngine::new_from_str_with_schema(&corpus.policy_text, schema)
        .expect("generated probe corpus should load");
    let load_elapsed = load_started.elapsed();
    let loaded_memory = memory_snapshot();

    let reload_started = Instant::now();
    engine
        .reload_from_str(&replacement.policy_text)
        .expect("generated replacement probe corpus should reload");
    let reload_elapsed = reload_started.elapsed();
    let reloaded_memory = memory_snapshot();

    let allow_request = allow_request();
    let forbid_request = forbid_request();
    let group_request = group_request();
    let no_match_request = no_match_request();

    let allow = measure_latency(
        || {
            black_box(
                engine
                    .evaluate(black_box(&allow_request))
                    .expect("allow probe request should evaluate"),
            );
        },
        samples,
    );
    let forbid = measure_latency(
        || {
            black_box(
                engine
                    .evaluate(black_box(&forbid_request))
                    .expect("forbid probe request should evaluate"),
            );
        },
        samples,
    );
    let group = measure_latency(
        || {
            black_box(
                engine
                    .evaluate(black_box(&group_request))
                    .expect("group probe request should evaluate"),
            );
        },
        samples,
    );
    let no_match = measure_latency(
        || {
            black_box(
                engine
                    .evaluate(black_box(&no_match_request))
                    .expect("no-match probe request should evaluate"),
            );
        },
        samples,
    );
    let listing = measure_latency(
        || {
            let policies = engine
                .list_policies(black_box(&no_match_request))
                .expect("probe policy listing should succeed");
            black_box(policies.policies().len());
        },
        samples,
    );
    let clone_all = measure_latency(
        || {
            black_box(
                engine
                    .policies()
                    .expect("probe policy cloning should succeed"),
            );
        },
        samples,
    );
    let queried_memory = memory_snapshot();

    println!("## Policy scale probe: corpus v{CORPUS_VERSION}, {policy_count} policies");
    println!();
    println!(
        "Generated deterministic corpus generations {} and {} of {:.2} MiB each; latency rows use {samples} samples after one warm-up operation.",
        corpus.generation,
        replacement.generation,
        corpus.policy_text.len() as f64 / (1_024.0 * 1_024.0)
    );
    println!();
    println!("### Load and reload");
    println!();
    println!("| Operation | Wall time |");
    println!("| --- | ---: |");
    println!(
        "| Generate two corpora | {} |",
        format_duration(generate_elapsed)
    );
    println!("| Parse schema | {} |", format_duration(schema_elapsed));
    println!(
        "| Build schema-validated engine | {} |",
        format_duration(load_elapsed)
    );
    println!(
        "| Atomic schema-validated reload | {} |",
        format_duration(reload_elapsed)
    );
    println!();
    println!("### Request-path latency");
    println!();
    println!("| Operation | Median | p95 |");
    println!("| --- | ---: | ---: |");
    print_latency_row("Evaluate allow", &allow);
    print_latency_row("Evaluate forbid", &forbid);
    print_latency_row("Evaluate group", &group);
    print_latency_row("Evaluate no match", &no_match);
    print_latency_row("List no match", &listing);
    print_latency_row("Clone all policies", &clone_all);
    println!();
    println!("### Process memory on Linux");
    println!();
    println!("| Phase | Resident MiB | Peak MiB |");
    println!("| --- | ---: | ---: |");
    println!(
        "| Process start | {} | {} |",
        format_mib(process_start_memory.resident_kib),
        format_mib(process_start_memory.peak_kib)
    );
    println!(
        "| Two corpora generated | {} | {} |",
        format_mib(generated_memory.resident_kib),
        format_mib(generated_memory.peak_kib)
    );
    println!(
        "| Validated engine loaded | {} | {} |",
        format_mib(loaded_memory.resident_kib),
        format_mib(loaded_memory.peak_kib)
    );
    println!(
        "| Atomic reload completed | {} | {} |",
        format_mib(reloaded_memory.resident_kib),
        format_mib(reloaded_memory.peak_kib)
    );
    println!(
        "| Request probes completed | {} | {} |",
        format_mib(queried_memory.resident_kib),
        format_mib(queried_memory.peak_kib)
    );
    println!();
    println!(
        "Approximate post-load RSS delta: {} MiB. Approximate additional atomic-reload peak above loaded RSS: {} MiB.",
        format_delta_mib(loaded_memory.resident_kib, generated_memory.resident_kib),
        format_delta_mib(reloaded_memory.peak_kib, loaded_memory.resident_kib)
    );
    println!();
    println!(
        "> RSS is allocator- and platform-dependent. Peak RSS is cumulative for this process, and released snapshots may remain in allocator arenas after they are dropped."
    );
}
