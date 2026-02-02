//! Example demonstrating how to track which policies are being matched using metrics.
//!
//! This example shows how to implement a metrics sink that counts how many times
//! each policy is matched during evaluations.
//!
//! Run with: cargo run --example policy_counter_sink --features observability

#[cfg(feature = "observability")]
use std::collections::HashMap;
#[cfg(feature = "observability")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "observability")]
use treetop_core::metrics::{EvaluationStats, MetricsSink, ReloadStats};
#[cfg(feature = "observability")]
use treetop_core::{Action, PolicyEngine, Principal, Request, Resource, User};

#[cfg(feature = "observability")]
/// A metrics sink that tracks which policies are matched and how often.
struct PolicyCounterSink {
    policy_counts: Arc<Mutex<HashMap<String, u64>>>,
    total_evaluations: Arc<Mutex<u64>>,
}

#[cfg(feature = "observability")]
impl PolicyCounterSink {
    fn new() -> Self {
        Self {
            policy_counts: Arc::new(Mutex::new(HashMap::new())),
            total_evaluations: Arc::new(Mutex::new(0)),
        }
    }

    fn print_stats(&self) {
        let counts = self.policy_counts.lock().unwrap();
        let total = self.total_evaluations.lock().unwrap();

        println!("\n=== Policy Match Statistics ===");
        println!("Total evaluations: {}", total);
        println!("\nPolicy match counts:");

        let mut sorted_policies: Vec<_> = counts.iter().collect();
        sorted_policies.sort_by(|a, b| b.1.cmp(a.1));

        for (policy_id, count) in sorted_policies {
            println!("  {}: {} matches", policy_id, count);
        }

        if counts.is_empty() {
            println!("  (no policies matched)");
        }
    }
}

#[cfg(feature = "observability")]
impl MetricsSink for PolicyCounterSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        // Increment total evaluations
        if let Ok(mut total) = self.total_evaluations.lock() {
            *total += 1;
        }

        // Count matched policies
        if let Ok(mut counts) = self.policy_counts.lock() {
            for policy_id in &stats.matched_policies {
                *counts.entry(policy_id.clone()).or_insert(0) += 1;
            }
        }
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        println!("Policy reloaded - resetting counters");
        if let Ok(mut counts) = self.policy_counts.lock() {
            counts.clear();
        }
        if let Ok(mut total) = self.total_evaluations.lock() {
            *total = 0;
        }
    }
}

#[cfg(feature = "observability")]
fn main() {
    // Define some policies with explicit IDs
    let policies = r#"
        permit (
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"public"
        );
        
        permit (
            principal == User::"bob",
            action == Action::"write",
            resource == Document::"public"
        );
        
        permit (
            principal,
            action == Action::"read",
            resource == Document::"public"
        );
        
        forbid (
            principal == User::"charlie",
            action == Action::"delete",
            resource
        );
    "#;

    // Create engine and configure metrics sink
    let engine = PolicyEngine::new_from_str(policies).expect("Failed to create engine");
    let sink = Arc::new(PolicyCounterSink::new());
    treetop_core::metrics::set_sink(sink.clone());

    println!("Running policy evaluations...\n");

    // Test various requests
    let test_cases = vec![
        (
            "alice",
            "read",
            "public",
            "Alice reads public (should match 2 policies)",
        ),
        (
            "bob",
            "write",
            "public",
            "Bob writes public (should match 1 policy)",
        ),
        (
            "charlie",
            "delete",
            "public",
            "Charlie deletes (should match forbid policy)",
        ),
        (
            "david",
            "read",
            "public",
            "David reads public (should match 1 policy)",
        ),
        (
            "alice",
            "write",
            "private",
            "Alice writes private (should match no policies)",
        ),
    ];

    for (user, action, resource, description) in test_cases {
        println!("Test: {}", description);

        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: Action::new(action, None),
            resource: Resource::new("Document", resource),
        };

        match engine.evaluate(&request) {
            Ok(decision) => {
                let verdict = if matches!(decision, treetop_core::Decision::Allow { .. }) {
                    "ALLOWED"
                } else {
                    "DENIED"
                };
                println!("  Result: {}\n", verdict);
            }
            Err(e) => {
                println!("  Error: {}\n", e);
            }
        }
    }

    // Print statistics
    sink.print_stats();
}

#[cfg(not(feature = "observability"))]
fn main() {
    println!("This example requires the 'observability' feature.");
    println!("Run with: cargo run --example policy_counter_sink --features observability");
}
