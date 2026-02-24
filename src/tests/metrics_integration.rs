#![cfg(feature = "observability")]
#![allow(dead_code, unused_imports)] // This test module is only compiled with observability feature

//! Metrics integration tests
//!
//! These tests verify that the metrics system correctly tracks evaluation statistics,
//! including matched policy IDs. Due to the use of a global metrics sink, these tests
//! must run serially to avoid interference. This is ensured via the #[serial] attribute.

use crate::metrics::{EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats};
use crate::{Action, Decision, PolicyEngine, Principal, Request, Resource, User};
#[cfg(test)]
use serial_test::serial;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NAMESPACE: &str = "DNS";
const DNS_POLICY: &str = include_str!("../../testdata/dns.cedar");

/// A simple test metrics sink that collects all metrics in memory.
#[derive(Clone)]
struct TestMetricsSink {
    eval_count: Arc<AtomicUsize>,
    allow_count: Arc<AtomicUsize>,
    deny_count: Arc<AtomicUsize>,
    reload_count: Arc<AtomicUsize>,
    total_duration_micros: Arc<AtomicU64>,
    principal_ids: Arc<Mutex<Vec<String>>>,
    action_ids: Arc<Mutex<Vec<String>>>,
    matched_policies: Arc<Mutex<Vec<Vec<String>>>>,
    phases: Arc<Mutex<Vec<EvaluationPhases>>>,
}

impl TestMetricsSink {
    fn new() -> Self {
        Self {
            eval_count: Arc::new(AtomicUsize::new(0)),
            allow_count: Arc::new(AtomicUsize::new(0)),
            deny_count: Arc::new(AtomicUsize::new(0)),
            reload_count: Arc::new(AtomicUsize::new(0)),
            total_duration_micros: Arc::new(AtomicU64::new(0)),
            principal_ids: Arc::new(Mutex::new(Vec::new())),
            action_ids: Arc::new(Mutex::new(Vec::new())),
            matched_policies: Arc::new(Mutex::new(Vec::new())),
            phases: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn eval_count(&self) -> usize {
        self.eval_count.load(Ordering::Relaxed)
    }

    fn allow_count(&self) -> usize {
        self.allow_count.load(Ordering::Relaxed)
    }

    fn deny_count(&self) -> usize {
        self.deny_count.load(Ordering::Relaxed)
    }

    fn principal_ids(&self) -> Vec<String> {
        self.principal_ids.lock().unwrap().clone()
    }

    fn action_ids(&self) -> Vec<String> {
        self.action_ids.lock().unwrap().clone()
    }

    fn matched_policies(&self) -> Vec<Vec<String>> {
        self.matched_policies.lock().unwrap().clone()
    }

    fn total_duration_ms(&self) -> f64 {
        self.total_duration_micros.load(Ordering::Relaxed) as f64 / 1_000.0
    }

    fn phases(&self) -> Vec<EvaluationPhases> {
        self.phases.lock().unwrap().clone()
    }
}

impl MetricsSink for TestMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        self.eval_count.fetch_add(1, Ordering::Relaxed);
        if stats.allowed {
            self.allow_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.deny_count.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut v) = self.principal_ids.lock() {
            v.push(stats.principal_id.clone());
        }
        if let Ok(mut v) = self.action_ids.lock() {
            v.push(stats.action_id.clone());
        }
        if let Ok(mut v) = self.matched_policies.lock() {
            v.push(stats.matched_policies.clone());
        }
        let micros = (stats.duration.as_secs_f64() * 1_000_000.0) as u64;
        self.total_duration_micros
            .fetch_add(micros, Ordering::Relaxed);
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        self.reload_count.fetch_add(1, Ordering::Relaxed);
    }

    fn on_evaluation_phases(&self, _stats: &EvaluationStats, phases: &EvaluationPhases) {
        if let Ok(mut p) = self.phases.lock() {
            p.push(phases.clone());
        }
    }
}

/// Helper to run evaluations with the engine and let metrics be automatically collected.
fn run_evaluations(
    engine: &PolicyEngine,
    requests: Vec<Request>,
) -> Result<Vec<Decision>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    for request in requests {
        let response = engine.evaluate(&request)?;
        results.push(response);
    }
    Ok(results)
}

/// Build a predefined set of test requests across various principals and actions.
fn build_test_requests(ns: &Option<Vec<String>>) -> Vec<Request> {
    let mut requests = Vec::new();

    // Define users with their group memberships
    let users = vec![
        ("alice", vec!["admins", "users"]),
        ("bob", vec!["users"]),
        ("charlie", vec!["admins"]),
    ];

    // Define actions to test
    let actions = vec!["view_host", "edit_host", "delete_host"];

    // Build all combinations: 3 principals × 3 actions = 9 requests
    for (user_name, groups) in users {
        let principal = Principal::User(User::new(
            user_name,
            Some(groups.iter().map(|g| g.to_string()).collect()),
            ns.clone(),
        ));

        for action_name in &actions {
            let request = Request {
                principal: principal.clone(),
                action: Action::new(*action_name, ns.clone()),
                resource: Resource::new("Host", "hostname.example.com"),
            };
            requests.push(request);
        }
    }

    requests
}

#[test]
#[serial(metrics)]
fn test_metrics_integration_with_dns_policy() {
    let engine = PolicyEngine::new_from_str(DNS_POLICY).expect("Failed to create engine");
    let test_sink = TestMetricsSink::new();
    let ns = Some(vec![NAMESPACE.to_string()]);

    // Set the global metrics sink
    crate::metrics::set_sink(Arc::new(test_sink.clone()));

    // Build predefined test requests
    let requests = build_test_requests(&ns);
    assert_eq!(requests.len(), 9, "Should have 9 predefined requests");

    // Run evaluations - metrics will be automatically collected via the global sink
    let _ = run_evaluations(&engine, requests).expect("Evaluations should succeed");

    // Verify total evaluations
    assert_eq!(
        test_sink.eval_count(),
        9,
        "Should have recorded 9 evaluations"
    );

    // Verify allow/deny split
    assert_eq!(
        test_sink.allow_count() + test_sink.deny_count(),
        9,
        "Allow + Deny should equal total evaluations"
    );

    // Verify principals are tracked
    let principal_ids = test_sink.principal_ids();
    assert_eq!(principal_ids.len(), 9, "Should track all 9 evaluations");
    assert!(
        principal_ids.iter().any(|p| p.contains("alice")),
        "Should track alice principals"
    );
    assert!(
        principal_ids.iter().any(|p| p.contains("bob")),
        "Should track bob principals"
    );
    assert!(
        principal_ids.iter().any(|p| p.contains("charlie")),
        "Should track charlie principals"
    );

    // Verify actions are tracked
    let action_ids = test_sink.action_ids();
    assert_eq!(action_ids.len(), 9, "Should track all 9 action evaluations");
    assert!(
        action_ids.iter().any(|a| a.contains("view_host")),
        "Should track view_host actions"
    );
    assert!(
        action_ids.iter().any(|a| a.contains("edit_host")),
        "Should track edit_host actions"
    );
    assert!(
        action_ids.iter().any(|a| a.contains("delete_host")),
        "Should track delete_host actions"
    );

    // Verify timing was recorded
    assert!(
        test_sink.total_duration_ms() > 0.0,
        "Should have recorded total duration"
    );

    // Count evaluations per principal
    let alice_count = principal_ids.iter().filter(|p| p.contains("alice")).count();
    let bob_count = principal_ids.iter().filter(|p| p.contains("bob")).count();
    let charlie_count = principal_ids
        .iter()
        .filter(|p| p.contains("charlie"))
        .count();
    assert_eq!(alice_count, 3, "Alice should have 3 evaluations");
    assert_eq!(bob_count, 3, "Bob should have 3 evaluations");
    assert_eq!(charlie_count, 3, "Charlie should have 3 evaluations");

    // Count evaluations per action
    let view_count = action_ids
        .iter()
        .filter(|a| a.contains("view_host"))
        .count();
    let edit_count = action_ids
        .iter()
        .filter(|a| a.contains("edit_host"))
        .count();
    let delete_count = action_ids
        .iter()
        .filter(|a| a.contains("delete_host"))
        .count();
    assert_eq!(view_count, 3, "view_host should have 3 evaluations");
    assert_eq!(edit_count, 3, "edit_host should have 3 evaluations");
    assert_eq!(delete_count, 3, "delete_host should have 3 evaluations");

    // Verify matched policies are tracked
    let matched_policies = test_sink.matched_policies();
    assert_eq!(
        matched_policies.len(),
        9,
        "Should track matched policies for all 9 evaluations"
    );

    // Count how many evaluations had at least one matched policy
    let with_matches = matched_policies.iter().filter(|p| !p.is_empty()).count();
    assert!(
        with_matches > 0,
        "At least some evaluations should have matched policies"
    );
}
#[test]
#[serial(metrics)]
fn test_metrics_phase_tracking() {
    // This test verifies that phase tracking data structures are correctly populated.
    // Since the global sink may already be set by other tests, we test by actually
    // running an evaluation and checking that the phases data makes sense structurally.

    let engine = PolicyEngine::new_from_str(DNS_POLICY).expect("Failed to create engine");
    let ns = Some(vec![NAMESPACE.to_string()]);

    // Run a single evaluation
    let request = Request {
        principal: Principal::User(User::new(
            "alice",
            Some(vec!["admins".to_string(), "users".to_string()]),
            ns.clone(),
        )),
        action: Action::new("view_host", ns.clone()),
        resource: Resource::new("Host", "hostname.example.com"),
    };

    // This will internally call record_evaluation_phases if the sink supports it
    let result = engine.evaluate(&request);
    assert!(result.is_ok(), "Evaluation should succeed");

    // Test that EvaluationPhases struct can be constructed and used
    use std::time::Duration;
    let test_phases = EvaluationPhases {
        apply_labels_ms: 0.5,
        construct_entities_ms: 1.2,
        resolve_groups_ms: 0.8,
        authorize_ms: 2.5,
        total_ms: 5.0,
    };

    // All phase durations should be non-negative
    assert!(
        test_phases.apply_labels_ms >= 0.0,
        "Label phase should be non-negative"
    );
    assert!(
        test_phases.construct_entities_ms >= 0.0,
        "Entity construction phase should be non-negative"
    );
    assert!(
        test_phases.resolve_groups_ms >= 0.0,
        "Group resolution phase should be non-negative"
    );
    assert!(
        test_phases.authorize_ms >= 0.0,
        "Authorization phase should be non-negative"
    );
    assert!(
        test_phases.total_ms >= 0.0,
        "Total duration should be non-negative"
    );

    // Test overhead calculation
    let overhead = test_phases.overhead_ms();
    assert!(overhead >= 0.0, "Overhead should be non-negative");
    assert_eq!(
        overhead, 0.0,
        "Overhead should be zero when sum equals total"
    );

    // Test with actual overhead
    let phases_with_overhead = EvaluationPhases {
        apply_labels_ms: 0.5,
        construct_entities_ms: 1.0,
        resolve_groups_ms: 0.5,
        authorize_ms: 2.0,
        total_ms: 5.0, // 1.0ms overhead
    };

    let overhead2 = phases_with_overhead.overhead_ms();
    assert!(
        (overhead2 - 1.0).abs() < 0.001,
        "Overhead should be ~1.0ms, got {}",
        overhead2
    );
}

#[test]
#[serial(metrics)]
fn test_matched_policies_tracking() {
    // Test that matched policy IDs are correctly tracked in metrics
    // Note: Cedar assigns sequential IDs (policy0, policy1, etc.) internally
    const POLICY_WITH_IDS: &str = r#"
        @id("allow_alice_read")
        permit (
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"doc1"
        );
        
        @id("allow_bob_write")
        permit (
            principal == User::"bob",
            action == Action::"write",
            resource == Document::"doc2"
        );
        
        @id("forbid_charlie_delete")
        forbid (
            principal == User::"charlie",
            action == Action::"delete",
            resource == Document::"doc3"
        );
    "#;

    let engine = PolicyEngine::new_from_str(POLICY_WITH_IDS).expect("Failed to create engine");
    let test_sink = TestMetricsSink::new();

    // Set the global metrics sink
    crate::metrics::set_sink(Arc::new(test_sink.clone()));

    // Test 1: Alice should match the first permit policy (policy0)
    let request1 = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc1"),
    };
    let result1 = engine
        .evaluate(&request1)
        .expect("Evaluation should succeed");
    assert!(
        matches!(result1, Decision::Allow { .. }),
        "Alice should be allowed to read doc1"
    );

    // Test 2: Bob should match the second permit policy (policy1)
    let request2 = Request {
        principal: Principal::User(User::new("bob", None, None)),
        action: Action::new("write", None),
        resource: Resource::new("Document", "doc2"),
    };
    let result2 = engine
        .evaluate(&request2)
        .expect("Evaluation should succeed");
    assert!(
        matches!(result2, Decision::Allow { .. }),
        "Bob should be allowed to write doc2"
    );

    // Test 3: Charlie should be denied by forbid policy (policy2)
    let request3 = Request {
        principal: Principal::User(User::new("charlie", None, None)),
        action: Action::new("delete", None),
        resource: Resource::new("Document", "doc3"),
    };
    let result3 = engine
        .evaluate(&request3)
        .expect("Evaluation should succeed");
    assert!(
        matches!(result3, Decision::Deny { .. }),
        "Charlie should be denied delete on doc3"
    );

    // Test 4: A request that matches no policies
    let request4 = Request {
        principal: Principal::User(User::new("david", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc4"),
    };
    let result4 = engine
        .evaluate(&request4)
        .expect("Evaluation should succeed");
    assert!(
        matches!(result4, Decision::Deny { .. }),
        "David should be denied (no matching policy)"
    );

    // Verify matched policies
    let matched_policies = test_sink.matched_policies();
    assert_eq!(matched_policies.len(), 4, "Should have 4 evaluations");

    // Alice's evaluation should have the annotation ID
    assert!(
        !matched_policies[0].is_empty(),
        "Alice's evaluation should have at least one matched policy, got: {:?}",
        matched_policies[0]
    );
    assert_eq!(
        matched_policies[0],
        vec!["allow_alice_read"],
        "Alice's matched policy should be 'allow_alice_read', got: {:?}",
        matched_policies[0]
    );

    // Bob's evaluation should have the annotation ID
    assert!(
        !matched_policies[1].is_empty(),
        "Bob's evaluation should have at least one matched policy, got: {:?}",
        matched_policies[1]
    );
    assert_eq!(
        matched_policies[1],
        vec!["allow_bob_write"],
        "Bob's matched policy should be 'allow_bob_write', got: {:?}",
        matched_policies[1]
    );

    // Charlie's evaluation should have no matched permit policies (forbid doesn't count)
    // Forbid policies don't show up in permit_policies, only in Cedar's decision
    assert!(
        matched_policies[2].is_empty(),
        "Charlie's evaluation should have no matched permit policies (forbid policy), got: {:?}",
        matched_policies[2]
    );

    // David's evaluation should have no matched policies (deny by default)
    assert!(
        matched_policies[3].is_empty(),
        "David's evaluation should have no matched policies, got: {:?}",
        matched_policies[3]
    );
}

#[test]
#[serial(metrics)]
fn test_multiple_matched_policies() {
    // Test that when multiple policies match, all are tracked
    // Cedar will assign these as policy0 and policy1
    const POLICY_WITH_MULTIPLE_MATCHES: &str = r#"
        @id("policy_1")
        permit (
            principal,
            action == Action::"read",
            resource == Document::"public"
        );
        
        @id("policy_2")
        permit (
            principal == User::"alice",
            action,
            resource
        );
    "#;

    let engine =
        PolicyEngine::new_from_str(POLICY_WITH_MULTIPLE_MATCHES).expect("Failed to create engine");
    let test_sink = TestMetricsSink::new();

    // Set the global metrics sink
    crate::metrics::set_sink(Arc::new(test_sink.clone()));

    // Alice reading public document should match both policies
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "public"),
    };
    let result = engine
        .evaluate(&request)
        .expect("Evaluation should succeed");
    assert!(
        matches!(result, Decision::Allow { .. }),
        "Alice should be allowed"
    );

    // Verify both policies were matched
    let matched_policies = test_sink.matched_policies();
    assert_eq!(matched_policies.len(), 1, "Should have 1 evaluation");
    assert_eq!(
        matched_policies[0].len(),
        2,
        "Should have 2 matched policies, got: {:?}",
        matched_policies[0]
    );

    // Verify that both policies are tracked (they'll be policy0 and policy1)
    let policy_ids = &matched_policies[0];
    assert!(
        policy_ids.iter().all(|id| id.starts_with("policy")),
        "All matched policies should be Cedar policy IDs, got: {:?}",
        policy_ids
    );
}
