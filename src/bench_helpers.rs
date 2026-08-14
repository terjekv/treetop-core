//! Thin benchmark-only wrappers around crate-private hot paths.
//!
//! The module is exposed only through the non-default `bench-internal` feature
//! so benchmark targets can measure production implementations without making
//! those internals part of the normal public API.

use cedar_policy::{PrincipalConstraint, ResourceConstraint};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::PolicyEngine;
use crate::error::PolicyError;
use crate::loader;
use crate::metrics::{
    EvaluationObservation, EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats,
};
use crate::policy_match;
use crate::query;
use crate::timers::PhaseTimer;
use crate::types::{Action, AttrValue, Decision, Principal, Request, Resource, User};

pub fn precompute_permit_policies_len(set: &cedar_policy::PolicySet) -> usize {
    loader::precompute_permit_policies(set)
        .expect("benchmark policies must have valid static metadata")
        .len()
}

fn sample_principal_query_user() -> query::PrincipalQuery {
    query::PrincipalQuery::for_user("alice", &["admins"], &[])
        .expect("benchmark principal query must build")
}

fn sample_resource_query() -> query::ResourceQuery {
    let res = Resource::new("Host", "web-01.example.com")
        .with_attr("name", AttrValue::String("web-01.example.com".to_string()));
    query::ResourceQuery::from_resource(&res).expect("benchmark resource query must build")
}

pub fn policy_match_principal_eq() -> u8 {
    let principal = sample_principal_query_user();
    let constraint = PrincipalConstraint::Eq(principal.uid.clone());
    u8::from(policy_match::principal_match_reason(constraint, &principal).is_some())
}

pub fn policy_match_principal_in() -> u8 {
    let principal = sample_principal_query_user();
    let parent = principal
        .parents
        .iter()
        .next()
        .expect("benchmark principal must have a parent")
        .clone();
    let constraint = PrincipalConstraint::In(parent);
    u8::from(policy_match::principal_match_reason(constraint, &principal).is_some())
}

pub fn policy_match_principal_any() -> u8 {
    let principal = sample_principal_query_user();
    let constraint = PrincipalConstraint::Any;
    u8::from(policy_match::principal_match_reason(constraint, &principal).is_some())
}

pub fn policy_match_principal_is_in() -> u8 {
    let principal = sample_principal_query_user();
    let parent = principal
        .parents
        .iter()
        .next()
        .expect("benchmark principal must have a parent")
        .clone();
    let constraint =
        PrincipalConstraint::IsIn("User".parse().expect("benchmark type must parse"), parent);
    u8::from(policy_match::principal_match_reason(constraint, &principal).is_some())
}

pub fn policy_match_resource_eq() -> u8 {
    let resource = sample_resource_query();
    let constraint = ResourceConstraint::Eq(resource.uid.clone());
    u8::from(
        policy_match::resource_match_reason(constraint, Some(&resource))
            .flatten()
            .is_some(),
    )
}

pub fn policy_match_resource_any() -> u8 {
    let resource = sample_resource_query();
    let constraint = ResourceConstraint::Any;
    u8::from(
        policy_match::resource_match_reason(constraint, Some(&resource))
            .flatten()
            .is_some(),
    )
}

pub fn policy_match_resource_is_in() -> u8 {
    let resource = sample_resource_query();
    let constraint = ResourceConstraint::IsIn(
        "Host".parse().expect("benchmark type must parse"),
        resource.uid.clone(),
    );
    u8::from(
        policy_match::resource_match_reason(constraint, Some(&resource))
            .flatten()
            .is_some(),
    )
}

pub fn query_user_with_groups(
    group_count: usize,
    namespace_depth: usize,
) -> Result<usize, PolicyError> {
    let groups: Vec<String> = (0..group_count).map(|idx| format!("group_{idx}")).collect();
    let group_refs: Vec<&str> = groups.iter().map(String::as_str).collect();

    let namespace: Vec<String> = (0..namespace_depth).map(|idx| format!("Ns{idx}")).collect();
    let namespace_refs: Vec<&str> = namespace.iter().map(String::as_str).collect();

    let query = query::PrincipalQuery::for_user("alice", &group_refs, &namespace_refs)?;
    Ok(query.parents.len() + query.type_name.len() + query.uid.to_string().len())
}

pub fn query_group(namespace_depth: usize) -> Result<usize, PolicyError> {
    let namespace: Vec<String> = (0..namespace_depth).map(|idx| format!("Ns{idx}")).collect();
    let namespace_refs: Vec<&str> = namespace.iter().map(String::as_str).collect();
    let query = query::PrincipalQuery::for_group("admins", &namespace_refs)?;
    Ok(query.parents.len() + query.type_name.len() + query.uid.to_string().len())
}

pub fn query_resource(namespace_depth: usize) -> Result<usize, PolicyError> {
    let namespace: Vec<String> = (0..namespace_depth).map(|idx| format!("Ns{idx}")).collect();
    let kind = if namespace.is_empty() {
        "Host".to_string()
    } else {
        format!("{}::Host", namespace.join("::"))
    };
    let resource = Resource::new(kind, "web-01.example.com");
    let query = query::ResourceQuery::from_resource(&resource)?;
    Ok(query.uid.to_string().len() + query.type_name.len())
}

pub fn phase_timer_overhead(iters: usize) -> u128 {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let _timer = PhaseTimer::new(&mut total);
    }
    total.as_nanos()
}

#[derive(Default)]
struct CountingSink {
    eval_count: AtomicU64,
    eval_phase_count: AtomicU64,
    reload_count: AtomicU64,
}

impl MetricsSink for CountingSink {
    fn on_evaluation(&self, _stats: &EvaluationStats) {
        self.eval_count.fetch_add(1, Ordering::Relaxed);
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        self.reload_count.fetch_add(1, Ordering::Relaxed);
    }

    fn on_evaluation_phases(&self, _stats: &EvaluationStats, _phases: &EvaluationPhases) {
        self.eval_phase_count.fetch_add(1, Ordering::Relaxed);
    }
}

static METRICS_SINK: LazyLock<Arc<CountingSink>> = LazyLock::new(|| {
    let sink = Arc::new(CountingSink::default());
    crate::metrics::set_sink(sink.clone());
    sink
});

static METRICS_STATS: LazyLock<EvaluationStats> = LazyLock::new(|| EvaluationStats {
    duration: Duration::from_micros(5),
    allowed: true,
    action_id: r#"Action::"view_host""#.to_string(),
    matched_policies: vec!["policy0".to_string(), "policy1".to_string()],
});

static METRICS_PHASES: LazyLock<EvaluationPhases> = LazyLock::new(|| EvaluationPhases {
    apply_labels_ms: 0.01,
    construct_entities_ms: 0.02,
    resolve_groups_ms: 0.03,
    authorize_ms: 0.04,
    total_ms: 0.12,
});

pub fn metrics_record_evaluation(iters: usize) -> u64 {
    let _sink = &*METRICS_SINK;
    for _ in 0..iters {
        let sink = crate::metrics::get_sink();
        crate::metrics::record_evaluation_with_phases(&sink, &METRICS_STATS, &METRICS_PHASES);
    }
    METRICS_SINK.eval_count.load(Ordering::Relaxed)
}

pub fn metrics_record_evaluation_phases(iters: usize) -> u64 {
    let _sink = &*METRICS_SINK;
    for _ in 0..iters {
        let sink = crate::metrics::get_sink();
        crate::metrics::record_evaluation_with_phases(&sink, &METRICS_STATS, &METRICS_PHASES);
    }
    METRICS_SINK.eval_phase_count.load(Ordering::Relaxed)
}

pub fn metrics_record_reload(iters: usize) -> u64 {
    let _sink = &*METRICS_SINK;
    for _ in 0..iters {
        crate::metrics::record_reload();
    }
    METRICS_SINK.reload_count.load(Ordering::Relaxed)
}

const METRICS_EVALUATION_POLICY: &str = r#"
    @id("allow_metrics_1")
    permit(principal, action == App::Core::Action::"view_host", resource is Host);

    @id("allow_metrics_2")
    permit(principal == User::"target", action == App::Core::Action::"view_host", resource);
"#;

static METRICS_ENGINE: LazyLock<PolicyEngine> = LazyLock::new(|| {
    PolicyEngine::new_from_str(METRICS_EVALUATION_POLICY)
        .expect("metrics benchmark policy must compile")
});

static METRICS_REQUEST: LazyLock<Request> = LazyLock::new(|| Request {
    principal: Principal::User(User::new("target", None, None)),
    action: Action::new(
        "view_host",
        Some(vec!["App".to_string(), "Core".to_string()]),
    ),
    resource: Resource::new("Host", "web-01.example.com"),
});

struct DisabledEvaluationSink;

impl MetricsSink for DisabledEvaluationSink {
    fn enabled(&self) -> bool {
        false
    }

    fn on_evaluation(&self, _stats: &EvaluationStats) {}

    fn on_reload(&self, _stats: &ReloadStats) {}
}

#[derive(Default)]
struct LegacyEvaluationSink {
    score: AtomicU64,
}

impl MetricsSink for LegacyEvaluationSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        let score = u64::from(stats.allowed)
            .wrapping_add(stats.duration.as_nanos() as u64)
            .wrapping_add(stats.action_id.len() as u64)
            .wrapping_add(stats.matched_policies.len() as u64);
        self.score.fetch_add(score, Ordering::Relaxed);
    }

    fn on_reload(&self, _stats: &ReloadStats) {}

    fn on_evaluation_phases(&self, _stats: &EvaluationStats, phases: &EvaluationPhases) {
        self.score
            .fetch_add(phases.total_ms.to_bits(), Ordering::Relaxed);
    }
}

#[derive(Default)]
struct BorrowedEvaluationSink {
    score: AtomicU64,
}

impl MetricsSink for BorrowedEvaluationSink {
    fn on_evaluation_observation(&self, observation: &EvaluationObservation<'_>) {
        let namespace_len = observation
            .action
            .namespace()
            .iter()
            .map(String::len)
            .sum::<usize>();
        let score = u64::from(observation.allowed)
            .wrapping_add(observation.duration.as_nanos() as u64)
            .wrapping_add(observation.action.id().len() as u64)
            .wrapping_add(namespace_len as u64)
            .wrapping_add(observation.phases.total_ms.to_bits());
        self.score.fetch_add(score, Ordering::Relaxed);
    }

    fn on_evaluation(&self, _stats: &EvaluationStats) {}

    fn on_reload(&self, _stats: &ReloadStats) {}
}

fn run_metrics_evaluations(iters: usize) -> u64 {
    let mut score = 0u64;
    for _ in 0..iters {
        let decision = METRICS_ENGINE
            .evaluate(&METRICS_REQUEST)
            .expect("metrics benchmark request must evaluate");
        score = score.wrapping_add(match decision {
            Decision::Allow { policies, .. } => policies.len() as u64,
            Decision::Deny { .. } => 0,
        });
    }
    score
}

pub fn metrics_evaluate_disabled(iters: usize) -> u64 {
    crate::metrics::set_sink(Arc::new(DisabledEvaluationSink));
    run_metrics_evaluations(iters)
}

pub fn metrics_evaluate_legacy(iters: usize) -> u64 {
    let sink = Arc::new(LegacyEvaluationSink::default());
    crate::metrics::set_sink(sink.clone());
    run_metrics_evaluations(iters).wrapping_add(sink.score.load(Ordering::Relaxed))
}

pub fn metrics_evaluate_borrowed(iters: usize) -> u64 {
    let sink = Arc::new(BorrowedEvaluationSink::default());
    crate::metrics::set_sink(sink.clone());
    run_metrics_evaluations(iters).wrapping_add(sink.score.load(Ordering::Relaxed))
}
