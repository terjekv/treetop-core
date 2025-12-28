# Metrics

Treetop-core provides vendor-agnostic metrics collection via a pluggable sink pattern. This allows you to send evaluation and reload metrics to any backend (Prometheus, OpenTelemetry, CloudWatch, Datadog, etc.) without the library imposing a dependency on a specific metrics framework.

## Enabling Observability

Add the `observability` feature to your `Cargo.toml`:

```toml
[dependencies]
treetop-core = { version = "0.0.13", features = ["observability"] }
```

Without this feature, the metrics and tracing infrastructure are not included, keeping the core library lightweight.

## Quick Start

1. Implement the `MetricsSink` trait
2. Call `set_sink()` once at application startup
3. Metrics will be automatically collected and routed to your implementation

## Core Concepts

### MetricsSink Trait

The `MetricsSink` trait has two methods:

- **`on_evaluation(&self, stats: &EvaluationStats)`** – called after each policy evaluation
- **`on_reload(&self, stats: &ReloadStats)`** – called after each policy reload

Both methods are invoked synchronously in the hot path, so implementations should be fast and non-blocking.

### EvaluationStats

```rust
pub struct EvaluationStats {
    pub duration: Duration,      // Total evaluation time
    pub allowed: bool,           // true = Allow, false = Deny
    pub principal_id: String,    // e.g., "User::alice"
    pub action_id: String,       // e.g., "Action::view_host"
}
```

### ReloadStats

```rust
pub struct ReloadStats {
    pub reload_time: SystemTime,  // When the reload completed
}
```

## Examples

See also the [../examples/](../examples/)

### Prometheus

```rust
use prometheus::{IntCounter, Histogram, Registry, TextEncoder, Encoder};
use std::sync::Arc;
use treetop_core::metrics::{MetricsSink, EvaluationStats, ReloadStats};

struct PrometheusMetricsSink {
    evals_total: IntCounterVec,
    evals_allowed: IntCounterVec,
    evals_denied: IntCounterVec,
    eval_duration: HistogramVec,
    reloads_total: IntCounter,
}

impl PrometheusMetricsSink {
    fn new(registry: &prometheus::Registry) -> Result<Self, Box<dyn std::error::Error>> {
        let evals_total = IntCounterVec::new("policy_evals_total", "Total evaluations", &["principal", "action"])?;
        let evals_allowed = IntCounterVec::new("policy_evals_allowed_total", "Allowed decisions", &["principal", "action"])?;
        let evals_denied = IntCounterVec::new("policy_evals_denied_total", "Denied decisions", &["principal", "action"])?;
        let eval_duration = HistogramVec::new("policy_eval_duration_seconds", "Eval latency", &["principal", "action"])?;
        let reloads_total = IntCounter::new("policy_reloads_total", "Total reloads")?;

        registry.register(Box::new(evals_total.clone()))?;
        registry.register(Box::new(evals_allowed.clone()))?;
        registry.register(Box::new(evals_denied.clone()))?;
        registry.register(Box::new(eval_duration.clone()))?;
        registry.register(Box::new(reloads_total.clone()))?;

        Ok(Self {
            evals_total,
            evals_allowed,
            evals_denied,
            eval_duration,
            reloads_total,
        })
    }
}

impl MetricsSink for PrometheusMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        let _ = self.evals_total.with_label_values(&[&stats.principal_id, &stats.action_id]).inc();
        if stats.allowed {
            let _ = self.evals_allowed.with_label_values(&[&stats.principal_id, &stats.action_id]).inc();
        } else {
            let _ = self.evals_denied.with_label_values(&[&stats.principal_id, &stats.action_id]).inc();
        }
        let _ = self.eval_duration.with_label_values(&[&stats.principal_id, &stats.action_id]).observe(stats.duration.as_secs_f64());
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        let _ = self.reloads_total.inc();
    }
}

// In your main:
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = prometheus::Registry::new();
    let sink = Arc::new(PrometheusMetricsSink::new(&registry)?);
    treetop_core::set_sink(sink);

    // Metrics are now collected and available in the registry
    // Serve them on your /metrics endpoint
    Ok(())
}
```

### OpenTelemetry with Tracing

For OpenTelemetry integration, the library emits `tracing` events that you can pipe to OTel via `tracing-opentelemetry`:

```rust
use opentelemetry_jaeger::new_pipeline;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tracer = new_pipeline().install_simple()?;
    let telemetry = OpenTelemetryLayer::new(tracer);

    let subscriber = tracing_subscriber::registry().with(telemetry);
    tracing::subscriber::set_default(subscriber);

    // Now policy evaluations will emit tracing spans that are routed to Jaeger
    Ok(())
}
```

### CloudWatch Logs

```rust
use std::sync::Arc;
use treetop_core::metrics::{MetricsSink, EvaluationStats, ReloadStats};

struct CloudWatchMetricsSink {
    // Use aws-sdk-cloudwatch or similar
}

impl MetricsSink for CloudWatchMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        // Send metrics to CloudWatch
        println!(
            "Evaluation: {:?}ms, allowed: {}",
            stats.duration.as_millis(),
            stats.allowed
        );
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        println!("Policy reloaded");
    }
}

// Set it up:
let sink = Arc::new(CloudWatchMetricsSink {});
treetop_core::set_sink(sink);
```

### Simple In-Memory Counters

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use treetop_core::metrics::{MetricsSink, EvaluationStats, ReloadStats};

struct CounterSink {
    evals_total: AtomicU64,
    evals_allowed: AtomicU64,
    evals_denied: AtomicU64,
    reloads_total: AtomicU64,
}

impl MetricsSink for CounterSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        self.evals_total.fetch_add(1, Ordering::Relaxed);
        if stats.allowed {
            self.evals_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.evals_denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        self.reloads_total.fetch_add(1, Ordering::Relaxed);
    }
}

// Usage:
let sink = Arc::new(CounterSink {
    evals_total: AtomicU64::new(0),
    evals_allowed: AtomicU64::new(0),
    evals_denied: AtomicU64::new(0),
    reloads_total: AtomicU64::new(0),
});

treetop_core::set_sink(sink.clone());

// Later, read the counts:
println!("Total evals: {}", sink.evals_total.load(Ordering::SeqCst));
println!("Allowed: {}", sink.evals_allowed.load(Ordering::SeqCst));
println!("Denied: {}", sink.evals_denied.load(Ordering::SeqCst));
```

## Best Practices

### 1. Set the Sink Once at Startup

```rust
#[tokio::main]
async fn main() {
    let sink = Arc::new(MyMetricsSink::new());
    treetop_core::set_sink(sink);

    // Now run your server, handle requests, etc.
    // Metrics are automatically collected.
}
```

### 2. Make Your Sink Thread-Safe

Because `PolicyEngine::evaluate()` is thread-safe and may be called from multiple threads concurrently, your `MetricsSink` implementation must be thread-safe. Use atomic types, mutexes, channels, or lock-free data structures as appropriate:

```rust
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;

struct ThreadSafeSink {
    counter: AtomicU64,        // Lock-free
    mutex_field: Mutex<String>, // Fine for non-hot paths
}
```

### 3. Keep on_evaluation() and on_reload() Fast

These methods are called in the hot path and should not block. Avoid:

- Blocking I/O
- Long computations
- Spinning locks

Instead, consider:

- Atomic operations for counters
- Channels to batch sends to a background worker
- Lock-free queues

```rust
impl MetricsSink for FastSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        // Fast: atomic increment
        self.counter.fetch_add(1, Ordering::Relaxed);
        
        // Slow (not recommended):
        // let _ = self.send_to_http_endpoint(stats).await;
    }
}
```

### 4. Serialize and Buffer for Remote Backends

If you need to send metrics to a remote system, use a background worker thread or async task:

```rust
use std::sync::mpsc;
use std::thread;

struct RemoteMetricsSink {
    tx: mpsc::Sender<EvaluationStats>,
}

impl RemoteMetricsSink {
    fn new() -> (Self, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        
        let handle = thread::spawn(move || {
            while let Ok(stats) = rx.recv() {
                // Send to remote service asynchronously
                // (or batch multiple stats together)
            }
        });

        (Self { tx }, handle)
    }
}

impl MetricsSink for RemoteMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        // Non-blocking: just push to channel
        let _ = self.tx.send(stats.clone());
    }

    fn on_reload(&self, _stats: &ReloadStats) {}
}
```

## What Metrics Should I Collect?

At minimum, consider these core metrics:

- **Total evaluations**: count of all `on_evaluation()` calls
- **Allow/Deny split**: separate counts for `stats.allowed == true/false`

Useful additions:

- **Evaluation latency histogram**: buckets or percentiles of `stats.duration`
- **Reload count**: count of `on_reload()` calls
- **Per-action/per-principal metrics** (if you add those to your sink): fine-grained insights
- **Phase timings**: time spent in label application, entity construction, authorization, group resolution

## Tracing Integration

The library already uses the `tracing` crate for structured logging. You can combine metrics collection with tracing by:

1. Collecting metrics in your `MetricsSink`
2. Using `tracing-opentelemetry` to export spans to OpenTelemetry (Jaeger, Tempo, etc.)

The `PolicyEngine::evaluate()` method emits the following structured spans:

- **`policy_evaluation`** (top-level): wraps the entire evaluation
  - Fields: `principal`, `action`, `resource`
- **`apply_labels`**: label registry application phase
- **`construct_entities`**: entity UID construction (P, A, R conversion)
- **`resolve_groups`**: group membership resolution
- **`authorize`**: Cedar authorization engine execution

Example with OpenTelemetry/Jaeger:

```rust
use tracing::info;
use treetop_core::metrics::{MetricsSink, EvaluationStats, ReloadStats};

struct InstrumentedSink;

impl MetricsSink for InstrumentedSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        info!(
            duration_ms = stats.duration.as_millis(),
            allowed = stats.allowed,
            "policy_evaluation_complete"
        );
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        info!("policy_reload_complete");
    }
}
```

Then pipe `tracing` to OpenTelemetry, Jaeger, or another backend.

## FAQ

## Memory Management in High-Load Systems

A common concern with metrics sinks is: **won't we run out of memory if we accumulate metrics?**

The answer is **no**, because your sink should **emit metrics immediately**, not accumulate them.

### ✅ Correct Pattern: Immediate Forwarding

```rust
// Counter-based sink (no buffering, constant memory)
struct PrometheusMetricsSink {
    evals_total: AtomicU64,
    evals_allowed: AtomicU64,
    evals_denied: AtomicU64,
}

impl MetricsSink for PrometheusMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        // Just increment atomic counter - O(1) memory, always
        self.evals_total.fetch_add(1, Ordering::Relaxed);
        if stats.allowed {
            self.evals_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.evals_denied.fetch_add(1, Ordering::Relaxed);
        }
        // Memory usage: constant (4 × u64 = 32 bytes)
    }

    fn on_reload(&self, _stats: &ReloadStats) {}
}
```

In this pattern:

- Each metric is a single atomic value that gets incremented
- Memory usage is **O(1)** - constant, regardless of throughput

- Works at any scale: 10/sec, 100k/sec, whatever

### ❌ Anti-Pattern: Accumulating Buffers

```rust
// DON'T do this in production!
struct BadMetricsSink {
    metrics: Mutex<Vec<EvaluationStats>>,  // ← This grows indefinitely!
}

impl MetricsSink for BadMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        self.metrics.lock().unwrap().push(stats.clone());  // Memory leak!
    }

    fn on_reload(&self, _stats: &ReloadStats) {}
}
```

This pattern will consume all available memory on a busy system because the vector keeps growing.

### Real-World Implementations

**Prometheus**: Use atomic counters and histograms with fixed-size buckets

```rust
let counter = prometheus::IntCounter::new("evals_total", "help")?;
counter.inc();  // O(1) memory
```

**OpenTelemetry**: Immediately export to collector (non-blocking)

```rust
let meter = opentelemetry::global::meter("app");
let counter = meter.u64_counter("evals_total").init();
counter.add(1, &[]);  // Queued for async export, doesn't block
```

**CloudWatch**: Batch and push asynchronously

```rust
// Use a background thread or tokio task
tokio::spawn(async {
    // Periodically send batch, clear buffer
    send_to_cloudwatch(metrics).await;
});
```

**Datadog**: Agent collects from stdout (DogStatsD format)

```rust
println!("evaluations.total:1|c");  // Immediate, stdout is buffered by OS
```

**Q: Can I change the sink at runtime?**  
A: Not with the current implementation. The sink is set once via `Lazy` initialization. If you need hot-swapping, wrap your sink in an `ArcSwap<dyn MetricsSink>` in your own code.

**Q: What if I don't call `set_sink()`?**  
A: The library uses a no-op sink by default, so there is zero overhead. You only pay for metrics you explicitly collect.

**Q: Do I need to handle serialization myself?**  
A: `EvaluationStats` and `ReloadStats` implement `serde::Serialize`, so you can easily convert them to JSON if needed.

**Q: Can I serialize/deserialize metrics?**  
A: Yes, both types are `Serialize`. Use `serde_json` or your preferred serializer.

## See Also

- [`MetricsSink`](https://docs.rs/treetop-core/latest/treetop_core/metrics/trait.MetricsSink.html)
- [`EvaluationStats`](https://docs.rs/treetop-core/latest/treetop_core/metrics/struct.EvaluationStats.html)
- [`ReloadStats`](https://docs.rs/treetop-core/latest/treetop_core/metrics/struct.ReloadStats.html)
- [`set_sink()`](https://docs.rs/treetop-core/latest/treetop_core/fn.set_sink.html)
