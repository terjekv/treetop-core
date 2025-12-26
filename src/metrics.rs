#![allow(dead_code)] // This entire file is feature-gated
//! Vendor-agnostic metrics collection via a pluggable sink.
//!
//! This module provides a trait-based sink pattern that allows consumers to
//! collect evaluation and reload metrics without tying the library to a specific
//! metrics backend (Prometheus, OpenTelemetry, CloudWatch, etc.).
//!
//! **Note:** This module is only available when the `observability` feature is enabled.
//! To run the doctests for this module, use: `cargo test --doc --features observability`
//!
//! ## Usage
//!
//! Implement the [`MetricsSink`] trait to process evaluation and reload events:
//!
//! ```ignore
//! use treetop_core::metrics::{MetricsSink, EvaluationStats, ReloadStats};
//! use std::sync::atomic::{AtomicU64, Ordering};
//! use std::sync::Arc;
//!
//! struct MyMetricsSink {
//!     evals: Arc<AtomicU64>,
//! }
//!
//! impl MetricsSink for MyMetricsSink {
//!     fn on_evaluation(&self, stats: &EvaluationStats) {
//!         self.evals.fetch_add(1, Ordering::Relaxed);
//!         eprintln!("Eval took {:?}, allowed: {}", stats.duration, stats.allowed);
//!     }
//!
//!     fn on_reload(&self, _stats: &ReloadStats) {
//!         eprintln!("Policy reloaded");
//!     }
//! }
//!
//! // Set the global sink:
//! treetop_core::metrics::set_sink(Arc::new(MyMetricsSink { evals: Arc::new(AtomicU64::new(0)) }));
//! ```
//!
//! For **Prometheus**, implement a sink that records to your Prometheus client,
//! or pipe [`tracing`] spans to OpenTelemetry.
//!
//! For **OpenTelemetry**, emit spans in `PolicyEngine::evaluate()` so consumers
//! can add OTel instrumentation via `tracing-opentelemetry`.

use serde::Serialize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::warn;

/// Snapshot of a policy evaluation, passed to [`MetricsSink::on_evaluation`].
///
/// This struct captures the essential metrics from a single evaluation:
/// the total duration and the decision outcome. It is serializable so
/// consumers can easily log or transmit it.
///
/// # Fields
///
/// * `duration` - Total wall-clock time for the evaluation, including
///   label application, entity construction, and Cedar authorization.
/// * `allowed` - `true` if the decision was `Allow`, `false` if `Deny`.
///
/// # Example
///
/// ```ignore
/// use treetop_core::metrics::EvaluationStats;
/// use std::time::Duration;
///
/// let stats = EvaluationStats {
///     duration: Duration::from_micros(500),
///     allowed: true,
///     principal_id: "User::alice".to_string(),
///     action_id: "Action::view_host".to_string(),
/// };
/// println!("Evaluation: {:?}ms, allowed: {}, principal: {}, action: {}",
///     stats.duration.as_millis(), stats.allowed, stats.principal_id, stats.action_id);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationStats {
    /// Total time spent evaluating the request
    pub duration: Duration,
    /// Whether the decision was Allow (true) or Deny (false)
    pub allowed: bool,
    /// Principal identifier (e.g., "User::alice")
    pub principal_id: String,
    /// Action identifier (e.g., "Action::view_host")
    pub action_id: String,
}

/// Detailed evaluation metrics broken down by phase.
///
/// This struct is useful for performance profiling and understanding where
/// time is spent during policy evaluation. All times are in milliseconds.
///
/// # Fields
///
/// * `apply_labels_ms` - Time spent applying label registry augmentation
/// * `construct_entities_ms` - Time spent converting atoms to Cedar EntityUids
/// * `resolve_groups_ms` - Time spent resolving group membership
/// * `authorize_ms` - Time spent in Cedar authorization engine
/// * `total_ms` - Total evaluation time (sum of phases + overhead)
///
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationPhases {
    /// Time spent in label application phase (milliseconds)
    pub apply_labels_ms: f64,
    /// Time spent in entity construction phase (milliseconds)
    pub construct_entities_ms: f64,
    /// Time spent in group resolution phase (milliseconds)
    pub resolve_groups_ms: f64,
    /// Time spent in Cedar authorization phase (milliseconds)
    pub authorize_ms: f64,
    /// Total evaluation time (milliseconds)
    pub total_ms: f64,
}

impl EvaluationPhases {
    /// Calculate overhead time (time not accounted for in measured phases)
    pub fn overhead_ms(&self) -> f64 {
        self.total_ms
            - (self.apply_labels_ms
                + self.construct_entities_ms
                + self.resolve_groups_ms
                + self.authorize_ms)
    }
}

///
/// This struct captures the timestamp when a policy reload completed.
/// Consumers can use this to track when policy updates take effect.
///
/// # Fields
///
/// * `reload_time` - System time when the reload operation finished.
///
/// # Example
///
/// ```ignore
/// use treetop_core::metrics::ReloadStats;
///
/// let stats = ReloadStats {
///     reload_time: std::time::SystemTime::now(),
/// };
/// println!("Policy reloaded at: {:?}", stats.reload_time);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ReloadStats {
    /// Time when the reload completed
    pub reload_time: std::time::SystemTime,
}

/// Trait for consuming evaluation and reload metrics.
///
/// Implement this trait to collect policy engine metrics and send them
/// to any backend (Prometheus, OpenTelemetry, CloudWatch, Datadog, etc.).
///
/// The trait is automatically invoked by `PolicyEngine` after each evaluation
/// and policy reload. Implementations should be thread-safe (hence the
/// `Send + Sync` bounds) and should not block, as they are called in the
/// hot path.
///
/// # Default Implementation
///
/// If no sink is explicitly set via [`set_sink`], a built-in no-op sink
/// is used, so there is zero performance overhead if metrics are not needed.
///
/// # Thread Safety
///
/// Implementations must be thread-safe because `PolicyEngine::evaluate` is
/// thread-safe and may be called concurrently from multiple threads.
/// Use atomic types, mutexes, or channels as appropriate.
///
/// # Example: Simple Counter Sink
///
/// ```ignore
/// use treetop_core::metrics::{MetricsSink, EvaluationStats, ReloadStats};
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use std::sync::Arc;
///
/// struct CounterSink {
///     evaluations: AtomicU64,
///     allows: AtomicU64,
///     denies: AtomicU64,
///     reloads: AtomicU64,
/// }
///
/// impl MetricsSink for CounterSink {
///     fn on_evaluation(&self, stats: &EvaluationStats) {
///         self.evaluations.fetch_add(1, Ordering::Relaxed);
///         if stats.allowed {
///             self.allows.fetch_add(1, Ordering::Relaxed);
///         } else {
///             self.denies.fetch_add(1, Ordering::Relaxed);
///         }
///     }
///
///     fn on_reload(&self, _stats: &ReloadStats) {
///         self.reloads.fetch_add(1, Ordering::Relaxed);
///     }
/// }
/// ```
pub trait MetricsSink: Send + Sync {
    /// Called after each policy evaluation with timing and decision info.
    ///
    /// This method is invoked synchronously after every call to
    /// `PolicyEngine::evaluate`, regardless of the decision outcome.
    /// It should return quickly to avoid blocking evaluation.
    fn on_evaluation(&self, stats: &EvaluationStats);

    /// Called after each policy reload.
    ///
    /// This method is invoked after a successful call to
    /// `PolicyEngine::reload_from_str`. It provides the timestamp
    /// when the reload completed.
    fn on_reload(&self, stats: &ReloadStats);

    /// Called with detailed phase-level timing information (optional).
    ///
    /// This is an optional method for sinks that want to break down
    /// evaluation time by phase. The default implementation does nothing.
    /// Override this in your implementation to collect per-phase metrics.
    fn on_evaluation_phases(&self, _stats: &EvaluationStats, _phases: &EvaluationPhases) {
        // Default: no-op
    }
}

/// No-op sink; metrics are silently dropped.
///
/// This is the default sink used if none is explicitly set via [`set_sink`].
/// It incurs zero overhead.
struct NoOpSink;

impl MetricsSink for NoOpSink {
    fn on_evaluation(&self, _stats: &EvaluationStats) {}
    fn on_reload(&self, _stats: &ReloadStats) {}
}

static SINK: OnceLock<Arc<dyn MetricsSink>> = OnceLock::new();

fn sink() -> Arc<dyn MetricsSink> {
    SINK.get_or_init(|| Arc::new(NoOpSink)).clone()
}

/// Set the global metrics sink.
///
/// All evaluation and reload events will be routed to this sink.
/// Call this **once at application startup**, before any policy evaluations,
/// to install your metrics collection implementation.
///
/// # Notes
///
/// * This function currently uses a static initializer, so the sink cannot
///   be hot-swapped after the first evaluation. Call this early in your
///   application startup before processing any requests.
/// * If you need dynamic sink replacement at runtime, consider using
///   a custom `Arc<ArcSwap<dyn MetricsSink>>` wrapper in your implementation.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use treetop_core::metrics::{set_sink, MetricsSink};
///
/// #[tokio::main]
/// async fn main() {
///     let my_sink = Arc::new(MyMetricsSink::new());
///     treetop_core::metrics::set_sink(my_sink);
///
///     // Now all policy evaluations will emit metrics
///     // ...
/// }
/// ```
pub fn set_sink(sink: Arc<dyn MetricsSink>) {
    // Try to set the sink. If it fails (already set), log a warning.
    if SINK.set(sink).is_err() {
        warn!(
            "Metrics sink was already initialized. Ignoring subsequent set_sink call. Set the sink before the first evaluation."
        );
    }
}

/// Get a reference to the current global sink.
///
/// This is an internal function used by the engine to dispatch metrics.
/// Most consumers should only call [`set_sink`] and implement [`MetricsSink`].
pub(crate) fn get_sink() -> Arc<dyn MetricsSink> {
    sink()
}

/// Record an evaluation event.
///
/// This is called internally by `PolicyEngine::evaluate` and should not be
/// called directly by consumers. It dispatches the metrics to the global sink.
pub(crate) fn record_evaluation(
    allowed: bool,
    duration: Duration,
    principal_id: String,
    action_id: String,
) {
    let sink = get_sink();
    sink.on_evaluation(&EvaluationStats {
        duration,
        allowed,
        principal_id,
        action_id,
    });
}

/// Record detailed phase-level metrics.
///
/// This is called internally by `PolicyEngine::evaluate` if phase timings
/// are collected. It dispatches the phase metrics to the sink.
pub(crate) fn record_evaluation_phases(
    allowed: bool,
    duration: Duration,
    principal_id: String,
    action_id: String,
    phases: EvaluationPhases,
) {
    let sink = get_sink();
    let stats = EvaluationStats {
        duration,
        allowed,
        principal_id,
        action_id,
    };
    sink.on_evaluation_phases(&stats, &phases);
}

/// Record a reload event.
///
/// This is called internally by `PolicyEngine::reload_from_str` and should
/// not be called directly by consumers. It dispatches the metrics to the
/// global sink.
pub(crate) fn record_reload() {
    let sink = get_sink();
    sink.on_reload(&ReloadStats {
        reload_time: std::time::SystemTime::now(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// A simple test sink that counts evaluations and reloads.
    #[allow(dead_code)]
    struct TestSink {
        eval_count: AtomicU64,
        allow_count: AtomicU64,
        deny_count: AtomicU64,
        reload_count: AtomicU64,
        last_eval_duration: OnceLock<std::sync::Mutex<Duration>>,
        was_called: AtomicBool,
    }

    #[allow(dead_code)]
    impl TestSink {
        fn new() -> Self {
            Self {
                eval_count: AtomicU64::new(0),
                allow_count: AtomicU64::new(0),
                deny_count: AtomicU64::new(0),
                reload_count: AtomicU64::new(0),
                last_eval_duration: OnceLock::new(),
                was_called: AtomicBool::new(false),
            }
        }
    }

    impl MetricsSink for TestSink {
        fn on_evaluation(&self, stats: &EvaluationStats) {
            self.was_called.store(true, Ordering::SeqCst);
            self.eval_count.fetch_add(1, Ordering::SeqCst);
            if stats.allowed {
                self.allow_count.fetch_add(1, Ordering::SeqCst);
            } else {
                self.deny_count.fetch_add(1, Ordering::SeqCst);
            }
            if let Ok(mut d) = self
                .last_eval_duration
                .get_or_init(|| std::sync::Mutex::new(Duration::ZERO))
                .lock()
            {
                *d = stats.duration;
            }
        }

        fn on_reload(&self, _stats: &ReloadStats) {
            self.reload_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_evaluation_stats_serialization() {
        let stats = EvaluationStats {
            duration: Duration::from_millis(42),
            allowed: true,
            principal_id: "User::test".to_string(),
            action_id: "Action::test".to_string(),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("42") || json.contains("0.042")); // millis or seconds in JSON
        assert!(json.contains("true"));
    }

    #[test]
    fn test_reload_stats_serialization() {
        let now = std::time::SystemTime::now();
        let stats = ReloadStats { reload_time: now };
        let json = serde_json::to_string(&stats).unwrap();
        // Just ensure it serializes without error
        assert!(!json.is_empty());
    }

    #[test]
    fn test_record_evaluation_with_no_op_sink() {
        // Default sink is no-op, so this should not panic
        record_evaluation(
            true,
            Duration::from_millis(100),
            "User::test".to_string(),
            "Action::test".to_string(),
        );
        record_evaluation(
            false,
            Duration::from_millis(50),
            "User::alice".to_string(),
            "Action::view".to_string(),
        );
    }

    #[test]
    fn test_record_reload_with_no_op_sink() {
        // Default sink is no-op, so this should not panic
        record_reload();
    }

    #[test]
    fn test_noop_sink_impl() {
        let sink = NoOpSink;
        let stats = EvaluationStats {
            duration: Duration::from_micros(1),
            allowed: true,
            principal_id: "User::test".to_string(),
            action_id: "Action::test".to_string(),
        };
        // Should not panic
        sink.on_evaluation(&stats);
        let reload_stats = ReloadStats {
            reload_time: std::time::SystemTime::now(),
        };
        sink.on_reload(&reload_stats);
    }

    #[test]
    fn test_evaluation_stats_clone() {
        let stats1 = EvaluationStats {
            duration: Duration::from_secs(1),
            allowed: false,
            principal_id: "User::test".to_string(),
            action_id: "Action::test".to_string(),
        };
        let stats2 = stats1.clone();
        assert_eq!(stats1.duration, stats2.duration);
        assert_eq!(stats1.allowed, stats2.allowed);
        assert_eq!(stats1.principal_id, stats2.principal_id);
        assert_eq!(stats1.action_id, stats2.action_id);
    }

    #[test]
    fn test_reload_stats_clone() {
        let now = std::time::SystemTime::now();
        let stats1 = ReloadStats { reload_time: now };
        let stats2 = stats1.clone();
        assert_eq!(stats1.reload_time, stats2.reload_time);
    }

    #[test]
    fn test_evaluation_stats_debug() {
        let stats = EvaluationStats {
            duration: Duration::from_micros(250),
            allowed: true,
            principal_id: "User::test".to_string(),
            action_id: "Action::test".to_string(),
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("EvaluationStats"));
        assert!(debug_str.contains("true"));
    }

    #[test]
    fn test_reload_stats_debug() {
        let stats = ReloadStats {
            reload_time: std::time::SystemTime::now(),
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("ReloadStats"));
    }
}
