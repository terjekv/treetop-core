//! Example: Prometheus metrics sink that doesn't accumulate memory.
//!
//! This demonstrates how a real sink would work: metrics are immediately
//! forwarded to Prometheus counters/histograms with fixed-size storage.
//!
//! The example also shows how to use on_evaluation_phases() to collect
//! detailed per-phase timing breakdowns (labels, entities, groups, authorize).
//!
//! To run: cargo run --example prometheus_sink --features observability

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use treetop_core::metrics::{EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats};

/// A Prometheus-style metrics sink that uses atomic counters and a fixed bucket histogram.
/// Memory stays constant: counters are scalars, histogram has fixed buckets.
struct PrometheusStyleSink {
    // Simple counters - no growth, just increments
    eval_count: AtomicU64,
    allow_count: AtomicU64,
    deny_count: AtomicU64,
    reload_count: AtomicU64,

    // Fixed histogram buckets for evaluation latency (seconds)
    bucket_bounds: &'static [f64],
    bucket_counts: Vec<AtomicU64>,
    sum_seconds: AtomicU64, // accumulate micros to avoid float atomics

    // Low-cardinality label slices (per principal / per action)
    per_user: Mutex<BTreeMap<String, u64>>,
    per_action: Mutex<BTreeMap<String, u64>>,
    per_user_sum_micros: Mutex<BTreeMap<String, u64>>,
    per_action_sum_micros: Mutex<BTreeMap<String, u64>>,

    // Phase-level timing counters (optional, for detailed profiling)
    labels_sum_micros: AtomicU64,
    entities_sum_micros: AtomicU64,
    groups_sum_micros: AtomicU64,
    authorize_sum_micros: AtomicU64,
}

impl PrometheusStyleSink {
    fn new() -> Self {
        // Prometheus-style latency buckets (seconds)
        // Customize as needed; keep count small to stay O(1)
        const BOUNDS: &[f64] = &[0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0];
        Self {
            eval_count: AtomicU64::new(0),
            allow_count: AtomicU64::new(0),
            deny_count: AtomicU64::new(0),
            reload_count: AtomicU64::new(0),
            bucket_bounds: BOUNDS,
            bucket_counts: (0..=BOUNDS.len()) // +Inf bucket
                .map(|_| AtomicU64::new(0))
                .collect(),
            sum_seconds: AtomicU64::new(0),
            per_user: Mutex::new(BTreeMap::new()),
            per_action: Mutex::new(BTreeMap::new()),
            per_user_sum_micros: Mutex::new(BTreeMap::new()),
            per_action_sum_micros: Mutex::new(BTreeMap::new()),
            labels_sum_micros: AtomicU64::new(0),
            entities_sum_micros: AtomicU64::new(0),
            groups_sum_micros: AtomicU64::new(0),
            authorize_sum_micros: AtomicU64::new(0),
        }
    }

    // Expose metrics (would be called by Prometheus scraper)
    fn export(&self) -> String {
        format!(
            "# HELP evaluations_total Total number of policy evaluations\n\
             # TYPE evaluations_total counter\n\
             evaluations_total {}\n\
             \n\
             # HELP evaluations_allowed_total Number of Allow decisions\n\
             # TYPE evaluations_allowed_total counter\n\
             evaluations_allowed_total {}\n\
             \n\
             # HELP evaluations_denied_total Number of Deny decisions\n\
             # TYPE evaluations_denied_total counter\n\
             evaluations_denied_total {}\n\
             \n\
             # HELP policy_reloads_total Total number of policy reloads\n\
             # TYPE policy_reloads_total counter\n\
             policy_reloads_total {}\n\
             \n\
             # HELP eval_duration_seconds Evaluation latency\n\
             # TYPE eval_duration_seconds histogram\n\
             {}\
             eval_duration_seconds_sum {}\n\
             eval_duration_seconds_count {}\n\
             \n\
             # HELP evaluations_per_user Total evaluations per user\n\
             # TYPE evaluations_per_user counter\n\
             {}\
             # HELP evaluations_per_action Total evaluations per action\n\
             # TYPE evaluations_per_action counter\n\
             {}\
             # HELP eval_duration_per_user_seconds Total evaluation time per user\n\
             # TYPE eval_duration_per_user_seconds counter\n\
             {}\
             # HELP eval_duration_per_action_seconds Total evaluation time per action\n\
             # TYPE eval_duration_per_action_seconds counter\n\
             {}\
             # HELP eval_phase_labels_seconds_total Time spent applying labels\n\
             # TYPE eval_phase_labels_seconds_total counter\n\
             eval_phase_labels_seconds_total {}\n\
             # HELP eval_phase_entities_seconds_total Time spent constructing entities\n\
             # TYPE eval_phase_entities_seconds_total counter\n\
             eval_phase_entities_seconds_total {}\n\
             # HELP eval_phase_groups_seconds_total Time spent resolving groups\n\
             # TYPE eval_phase_groups_seconds_total counter\n\
             eval_phase_groups_seconds_total {}\n\
             # HELP eval_phase_authorize_seconds_total Time spent in authorization\n\
             # TYPE eval_phase_authorize_seconds_total counter\n\
             eval_phase_authorize_seconds_total {}\n\
             ",
            self.eval_count.load(Ordering::Relaxed),
            self.allow_count.load(Ordering::Relaxed),
            self.deny_count.load(Ordering::Relaxed),
            self.reload_count.load(Ordering::Relaxed),
            self.export_histogram(),
            self.sum_seconds.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            self.eval_count.load(Ordering::Relaxed),
            self.export_per_user(),
            self.export_per_action(),
            self.export_per_user_duration(),
            self.export_per_action_duration(),
            self.labels_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            self.entities_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            self.groups_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            self.authorize_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
        )
    }

    fn export_histogram(&self) -> String {
        let mut out = String::new();
        let mut cumulative = 0;
        for (i, &bound) in self.bucket_bounds.iter().enumerate() {
            cumulative += self.bucket_counts[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "eval_duration_seconds_bucket{{le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        // +Inf bucket
        cumulative += self.bucket_counts.last().unwrap().load(Ordering::Relaxed);
        out.push_str(&format!(
            "eval_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\n"
        ));
        out
    }

    fn export_per_user(&self) -> String {
        let mut out = String::new();
        if let Ok(map) = self.per_user.lock() {
            for (user, count) in map.iter() {
                out.push_str(&format!(
                    "evaluations_per_user{{user=\"{user}\"}} {count}\n"
                ));
            }
        }
        out
    }

    fn export_per_action(&self) -> String {
        let mut out = String::new();
        if let Ok(map) = self.per_action.lock() {
            for (action, count) in map.iter() {
                out.push_str(&format!(
                    "evaluations_per_action{{action=\"{action}\"}} {count}\n"
                ));
            }
        }
        out
    }

    fn export_per_user_duration(&self) -> String {
        let mut out = String::new();
        if let Ok(map) = self.per_user_sum_micros.lock() {
            for (user, micros) in map.iter() {
                let secs = *micros as f64 / 1_000_000.0;
                out.push_str(&format!(
                    "eval_duration_per_user_seconds{{user=\"{user}\"}} {secs}\n"
                ));
            }
        }
        out
    }

    fn export_per_action_duration(&self) -> String {
        let mut out = String::new();
        if let Ok(map) = self.per_action_sum_micros.lock() {
            for (action, micros) in map.iter() {
                let secs = *micros as f64 / 1_000_000.0;
                out.push_str(&format!(
                    "eval_duration_per_action_seconds{{action=\"{action}\"}} {secs}\n"
                ));
            }
        }
        out
    }
}

impl MetricsSink for PrometheusStyleSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        // Immediately increment counters - no buffering, no memory growth
        self.eval_count.fetch_add(1, Ordering::Relaxed);
        if stats.allowed {
            self.allow_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.deny_count.fetch_add(1, Ordering::Relaxed);
        }

        // Histogram: find bucket, update count. Duration in seconds as f64; store sum in micros to avoid f64 atomics.
        let dur_secs = stats.duration.as_secs_f64();
        let idx = self
            .bucket_bounds
            .iter()
            .position(|b| dur_secs <= *b)
            .unwrap_or(self.bucket_bounds.len());
        self.bucket_counts[idx].fetch_add(1, Ordering::Relaxed);

        let dur_micros = (dur_secs * 1_000_000.0) as u64;
        self.sum_seconds.fetch_add(dur_micros, Ordering::Relaxed);

        // Low-cardinality labels: track per user and per action counts
        if let Ok(mut map) = self.per_user.lock() {
            *map.entry(stats.principal_id.clone()).or_insert(0) += 1;
        }
        if let Ok(mut map) = self.per_action.lock() {
            *map.entry(stats.action_id.clone()).or_insert(0) += 1;
        }

        // Track duration sum per user and per action
        if let Ok(mut map) = self.per_user_sum_micros.lock() {
            *map.entry(stats.principal_id.clone()).or_insert(0) += dur_micros;
        }
        if let Ok(mut map) = self.per_action_sum_micros.lock() {
            *map.entry(stats.action_id.clone()).or_insert(0) += dur_micros;
        }
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        self.reload_count.fetch_add(1, Ordering::Relaxed);
    }

    fn on_evaluation_phases(&self, _stats: &EvaluationStats, phases: &EvaluationPhases) {
        // Accumulate phase timing in microseconds (convert from ms)
        let labels_micros = (phases.apply_labels_ms * 1000.0) as u64;
        let entities_micros = (phases.construct_entities_ms * 1000.0) as u64;
        let groups_micros = (phases.resolve_groups_ms * 1000.0) as u64;
        let authorize_micros = (phases.authorize_ms * 1000.0) as u64;

        self.labels_sum_micros
            .fetch_add(labels_micros, Ordering::Relaxed);
        self.entities_sum_micros
            .fetch_add(entities_micros, Ordering::Relaxed);
        self.groups_sum_micros
            .fetch_add(groups_micros, Ordering::Relaxed);
        self.authorize_sum_micros
            .fetch_add(authorize_micros, Ordering::Relaxed);
    }
}

fn main() {
    println!("=== Prometheus-Style Sink example (manual output) ===\n");

    let sink = Arc::new(PrometheusStyleSink::new());

    // Simulated principals/actions to demonstrate per-label slices (low cardinality)
    const USERS: &[&str] = &["alice", "bob", "charlie"];
    const ACTIONS: &[&str] = &["view_host", "edit_host", "delete_host"];

    // Generate a small set of evaluations with jittered latency and labels.
    // Sleep is intentional to demonstrate histogram spread in the example output.
    // Jitter is deterministic (no external deps): a tiny LCG-based RNG with a small chance of larger outliers.
    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *seed
    }

    let mut rng = 42u64;
    for i in 0..150 {
        let user = USERS[i % USERS.len()];
        let action = ACTIONS[(i / USERS.len()) % ACTIONS.len()];

        // Mostly small latencies (< 2ms) with a small probability of larger outliers (5–150ms).
        let r = lcg(&mut rng);
        let dur = if r.is_multiple_of(20) {
            // ~5% of the time: heavier tail between 5ms and ~150ms
            let micros = 5_000 + (r % 30) * 5_000; // 5ms to 155ms
            Duration::from_micros(micros)
        } else {
            // ~95% of the time: sub-2ms with small jitter
            let micros = 300 + (r % 900); // 0.0003s – 0.0012s
            Duration::from_micros(micros)
        };

        // Simulate work taking `dur`
        thread::sleep(dur);

        let stats = EvaluationStats {
            duration: dur,
            // Simple allow/deny pattern to show both counters
            allowed: !(user == "bob" && action == "delete_host"),
            principal_id: format!("User::{user}"),
            action_id: format!("Action::{action}"),
        };
        sink.on_evaluation(&stats);

        // Also simulate phase-level breakdown (for demonstration)
        // In reality, these would come from the PolicyEngine
        let dur_ms = dur.as_secs_f64() * 1000.0;
        let phases = EvaluationPhases {
            apply_labels_ms: dur_ms * 0.05,       // ~5% labels
            construct_entities_ms: dur_ms * 0.15, // ~15% entities
            resolve_groups_ms: dur_ms * 0.10,     // ~10% groups
            authorize_ms: dur_ms * 0.65,          // ~65% authorize (bulk of time)
            total_ms: dur_ms,
        };
        sink.on_evaluation_phases(&stats, &phases);
    }

    // Export metrics (what Prometheus would scrape)
    println!("{}", sink.export());
    println!("After 150 evaluations: memory usage is constant (counters + fixed buckets)");
}
