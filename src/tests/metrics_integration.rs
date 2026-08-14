#![cfg(feature = "observability")]
//! Metrics integration tests
//!
//! These tests verify that the metrics system correctly tracks evaluation statistics,
//! including matched policy IDs. Tests that install a global sink run serially with
//! each other. Assertions also tolerate evaluations from unrelated parallel tests,
//! because the sink is deliberately process-wide.

use crate::metrics::{
    EvaluationObservation, EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats,
};
use crate::{Action, Decision, PolicyEngine, Principal, Request, Resource, User};
#[cfg(test)]
use serial_test::serial;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

    fn matched_policies(&self) -> Vec<Vec<String>> {
        self.matched_policies.lock().unwrap().clone()
    }

    fn action_ids(&self) -> Vec<String> {
        self.action_ids.lock().unwrap().clone()
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
        if let Ok(mut action_ids) = self.action_ids.lock() {
            action_ids.push(stats.action_id.clone());
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

type ObservedAction = (String, Vec<String>);

#[derive(Clone, Default)]
struct BorrowedTestSink {
    observation_count: Arc<AtomicUsize>,
    legacy_count: Arc<AtomicUsize>,
    actions: Arc<Mutex<Vec<ObservedAction>>>,
    matched_policies: Arc<Mutex<Vec<Vec<String>>>>,
}

impl MetricsSink for BorrowedTestSink {
    fn on_evaluation_observation(&self, observation: &EvaluationObservation<'_>) {
        self.observation_count.fetch_add(1, Ordering::Relaxed);
        self.actions.lock().unwrap().push((
            observation.action.id().to_owned(),
            observation.action.namespace().to_vec(),
        ));

        let mut policy_ids = observation
            .matched_policy_ids()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        policy_ids.sort();
        self.matched_policies.lock().unwrap().push(policy_ids);
    }

    fn on_evaluation(&self, _stats: &EvaluationStats) {
        self.legacy_count.fetch_add(1, Ordering::Relaxed);
    }

    fn on_reload(&self, _stats: &ReloadStats) {}
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
    assert!(
        test_sink.eval_count() >= 9,
        "Should have recorded at least the 9 requested evaluations"
    );

    // Verify allow/deny split
    assert_eq!(
        test_sink.allow_count() + test_sink.deny_count(),
        test_sink.eval_count(),
        "Every recorded evaluation should be classified as allow or deny"
    );

    // Verify timing was recorded
    assert!(
        test_sink.total_duration_ms() > 0.0,
        "Should have recorded total duration"
    );

    // Verify the fully qualified action dimension is available to consumers.
    let action_ids = test_sink.action_ids();
    for expected in ["view_host", "edit_host", "delete_host"] {
        let expected = format!(r#"DNS::Action::"{expected}""#);
        assert!(
            action_ids.iter().any(|action_id| action_id == &expected),
            "Should record action ID {expected}"
        );
    }

    // Verify matched policies are tracked
    let matched_policies = test_sink.matched_policies();
    assert_eq!(
        matched_policies.len(),
        test_sink.eval_count(),
        "Should track matched policies for every recorded evaluation"
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
    let engine = PolicyEngine::new_from_str(DNS_POLICY).expect("Failed to create engine");
    let test_sink = TestMetricsSink::new();
    crate::metrics::set_sink(Arc::new(test_sink.clone()));
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

    // The default observation adapter dispatches the legacy phase callback.
    let result = engine.evaluate(&request);
    assert!(result.is_ok(), "Evaluation should succeed");

    let observed = test_sink.phases();
    assert!(!observed.is_empty(), "a phase sample should be emitted");
    for observed in observed {
        let accounted = observed.apply_labels_ms
            + observed.construct_entities_ms
            + observed.resolve_groups_ms
            + observed.authorize_ms;
        assert!(
            accounted <= observed.total_ms,
            "phase timings must not overlap: accounted={accounted}, total={}",
            observed.total_ms
        );
    }

    // Test that EvaluationPhases struct can be constructed and used
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
fn test_borrowed_observation_reports_action_and_lazy_policy_ids() {
    const POLICY: &str = r#"
        @id("allow_read_1")
        permit(principal, action == App::Core::Action::"read", resource);

        @id("allow_read_2")
        permit(principal == User::"alice", action == App::Core::Action::"read", resource);

        @id("forbid_delete")
        forbid(principal == User::"charlie", action == App::Core::Action::"delete", resource);
    "#;

    let engine = PolicyEngine::new_from_str(POLICY).expect("policy should compile");
    let sink = BorrowedTestSink::default();
    crate::metrics::set_sink(Arc::new(sink.clone()));
    let namespace = Some(vec!["App".to_string(), "Core".to_string()]);

    for (user, action) in [
        ("alice", "read"),
        ("charlie", "delete"),
        ("david", "unmatched"),
    ] {
        engine
            .evaluate(&Request {
                principal: Principal::User(User::new(user, None, None)),
                action: Action::new(action, namespace.clone()),
                resource: Resource::new("Document", "doc1"),
            })
            .expect("request should evaluate");
    }

    assert_eq!(sink.observation_count.load(Ordering::Relaxed), 3);
    assert_eq!(sink.legacy_count.load(Ordering::Relaxed), 0);
    assert_eq!(
        *sink.actions.lock().unwrap(),
        vec![
            (
                "read".to_string(),
                vec!["App".to_string(), "Core".to_string()]
            ),
            (
                "delete".to_string(),
                vec!["App".to_string(), "Core".to_string()]
            ),
            (
                "unmatched".to_string(),
                vec!["App".to_string(), "Core".to_string()]
            ),
        ]
    );
    assert_eq!(
        *sink.matched_policies.lock().unwrap(),
        vec![
            vec!["allow_read_1".to_string(), "allow_read_2".to_string()],
            vec!["forbid_delete".to_string()],
            Vec::<String>::new(),
        ]
    );

    crate::metrics::set_sink(Arc::new(TestMetricsSink::new()));
}

struct PanickingSink;

impl MetricsSink for PanickingSink {
    fn on_evaluation(&self, _stats: &EvaluationStats) {
        panic!("metrics backends must not affect authorization");
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        panic!("metrics backends must not affect reloads");
    }
}

struct PanickingBorrowedSink;

impl MetricsSink for PanickingBorrowedSink {
    fn on_evaluation_observation(&self, _observation: &EvaluationObservation<'_>) {
        panic!("borrowed metrics backends must not affect authorization");
    }

    fn on_evaluation(&self, _stats: &EvaluationStats) {}

    fn on_reload(&self, _stats: &ReloadStats) {}
}

#[test]
#[serial(metrics)]
fn test_panicking_metrics_sink_is_isolated_from_engine_operations() {
    let engine =
        PolicyEngine::new_from_str(r#"permit(principal, action == Action::"read", resource);"#)
            .expect("policy should compile");
    crate::metrics::set_sink(Arc::new(PanickingSink));

    let decision = engine
        .evaluate(&Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "public"),
        })
        .expect("a metrics panic must not fail authorization");
    assert!(matches!(decision, Decision::Allow { .. }));

    crate::metrics::set_sink(Arc::new(PanickingBorrowedSink));
    let decision = engine
        .evaluate(&Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "public"),
        })
        .expect("a borrowed metrics panic must not fail authorization");
    assert!(matches!(decision, Decision::Allow { .. }));

    engine
        .reload_from_str(r#"permit(principal, action, resource);"#)
        .expect("a metrics panic must not fail policy reload");

    crate::metrics::set_sink(Arc::new(TestMetricsSink::new()));
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
    assert!(
        matched_policies
            .iter()
            .any(|ids| ids == &["allow_alice_read"]),
        "Alice's permit policy should be reported: {matched_policies:?}"
    );
    assert!(
        matched_policies
            .iter()
            .any(|ids| ids == &["allow_bob_write"]),
        "Bob's permit policy should be reported: {matched_policies:?}"
    );
    assert!(
        matched_policies
            .iter()
            .any(|ids| ids == &["forbid_charlie_delete"]),
        "Charlie's forbid policy should be reported: {matched_policies:?}"
    );
    assert!(
        matched_policies.iter().any(Vec::is_empty),
        "David's default-deny evaluation should report no policies: {matched_policies:?}"
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
    let policy_ids = matched_policies
        .iter()
        .find(|ids| ids.len() == 2 && ids.iter().all(|id| id.starts_with("policy")))
        .expect("the evaluation should report both matching policies");

    // Verify that both policies are tracked.
    assert!(
        policy_ids.iter().all(|id| id.starts_with("policy")),
        "All matched policies should be Cedar policy IDs, got: {:?}",
        policy_ids
    );
}
