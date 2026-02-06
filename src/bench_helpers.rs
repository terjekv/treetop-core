use cedar_policy::{PrincipalConstraint, ResourceConstraint};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::error::PolicyError;
use crate::loader;
use crate::metrics::{EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats};
use crate::policy_match;
use crate::query;
use crate::timers::PhaseTimer;
use crate::types::{AttrValue, Resource};

// This module exists to keep benchmarks small, targeted, and stable.
// - Bench code lives in benches/, but some hot-path helpers are pub(crate).
// - We expose thin wrappers here under the `bench-internal` feature so benches
//   can call real internals without duplicating logic or making them public API.
// - The feature is disabled in normal builds, so this has zero production impact.

pub fn precompute_permit_policies_len(set: &cedar_policy::PolicySet) -> usize {
    loader::precompute_permit_policies(set).len()
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
    policy_match::principal_match_reason(constraint, &principal)
        .is_some()
        .then_some(1)
        .unwrap_or(0)
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
    policy_match::principal_match_reason(constraint, &principal)
        .is_some()
        .then_some(1)
        .unwrap_or(0)
}

pub fn policy_match_principal_any() -> u8 {
    let principal = sample_principal_query_user();
    let constraint = PrincipalConstraint::Any;
    policy_match::principal_match_reason(constraint, &principal)
        .is_some()
        .then_some(1)
        .unwrap_or(0)
}

pub fn policy_match_principal_is_in() -> u8 {
    let principal = sample_principal_query_user();
    let parent = principal
        .parents
        .iter()
        .next()
        .expect("benchmark principal must have a parent")
        .clone();
    let constraint = PrincipalConstraint::IsIn("User".parse().unwrap(), parent);
    policy_match::principal_match_reason(constraint, &principal)
        .is_some()
        .then_some(1)
        .unwrap_or(0)
}

pub fn policy_match_resource_eq() -> u8 {
    let resource = sample_resource_query();
    let constraint = ResourceConstraint::Eq(resource.uid.clone());
    policy_match::resource_match_reason(constraint, Some(&resource))
        .flatten()
        .is_some()
        .then_some(1)
        .unwrap_or(0)
}

pub fn policy_match_resource_any() -> u8 {
    let resource = sample_resource_query();
    let constraint = ResourceConstraint::Any;
    policy_match::resource_match_reason(constraint, Some(&resource))
        .flatten()
        .is_some()
        .then_some(1)
        .unwrap_or(0)
}

pub fn policy_match_resource_is_in() -> u8 {
    let resource = sample_resource_query();
    let constraint = ResourceConstraint::IsIn("Host".parse().unwrap(), resource.uid.clone());
    policy_match::resource_match_reason(constraint, Some(&resource))
        .flatten()
        .is_some()
        .then_some(1)
        .unwrap_or(0)
}

pub fn query_user_with_groups(group_count: usize, namespace_depth: usize) -> Result<usize, PolicyError> {
    let groups: Vec<String> = (0..group_count).map(|idx| format!("group_{idx}")).collect();
    let group_refs: Vec<&str> = groups.iter().map(|g| g.as_str()).collect();

    let ns: Vec<String> = (0..namespace_depth).map(|idx| format!("Ns{idx}")).collect();
    let ns_refs: Vec<&str> = ns.iter().map(|n| n.as_str()).collect();

    let query = query::PrincipalQuery::for_user("alice", &group_refs, &ns_refs)?;
    Ok(query.parents.len() + query.type_name.len() + query.uid.to_string().len())
}

pub fn query_group(namespace_depth: usize) -> Result<usize, PolicyError> {
    let ns: Vec<String> = (0..namespace_depth).map(|idx| format!("Ns{idx}")).collect();
    let ns_refs: Vec<&str> = ns.iter().map(|n| n.as_str()).collect();
    let query = query::PrincipalQuery::for_group("admins", &ns_refs)?;
    Ok(query.parents.len() + query.type_name.len() + query.uid.to_string().len())
}

pub fn query_resource(namespace_depth: usize) -> Result<usize, PolicyError> {
    let namespace: Vec<String> = (0..namespace_depth).map(|idx| format!("Ns{idx}")).collect();
    let kind = if namespace.is_empty() {
        "Host".to_string()
    } else {
        format!("{}::Host", namespace.join("::"))
    };
    let res = Resource::new(kind, "web-01.example.com");
    let query = query::ResourceQuery::from_resource(&res)?;
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
    principal_id: "User::alice".to_string(),
    action_id: "Action::view_host".to_string(),
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
        crate::metrics::record_evaluation(&METRICS_STATS);
    }
    METRICS_SINK.eval_count.load(Ordering::Relaxed)
}

pub fn metrics_record_evaluation_phases(iters: usize) -> u64 {
    let _sink = &*METRICS_SINK;
    for _ in 0..iters {
        crate::metrics::record_evaluation_phases(&METRICS_STATS, &METRICS_PHASES);
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
