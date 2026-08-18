#[allow(
    dead_code,
    reason = "the shared fixture also serves the scale benchmark"
)]
#[path = "../benches/policy_scale_common.rs"]
mod policy_scale_common;

use std::time::Instant;

use policy_scale_common::{
    PR_SCALE_POLICY_COUNT, REVIEWERS_GROUP, ScaleCorpus, TARGET_DOCUMENT, TARGET_USER,
    configured_policy_count,
};
use treetop_core::{Action, AttrValue, Decision, PolicyEngine, Principal, Request, Resource, User};

fn request(user: &str, groups: Option<Vec<String>>, action: &str) -> Request {
    Request {
        principal: Principal::User(User::new(user, groups, None)),
        action: Action::new(action, None),
        resource: Resource::new("Document", TARGET_DOCUMENT)
            .with_attr("classification", AttrValue::String("public".to_string())),
    }
}

fn exercise_scale_corpus(policy_count: usize) {
    let generation_started = Instant::now();
    let corpus = ScaleCorpus::new(policy_count, 0);
    let generation_elapsed = generation_started.elapsed();

    let load_started = Instant::now();
    let engine =
        PolicyEngine::new_from_str_with_cedarschema(&corpus.policy_text, &corpus.schema_text)
            .expect("generated scale corpus should load with strict schema validation");
    let load_elapsed = load_started.elapsed();

    assert_eq!(
        engine
            .policies()
            .expect("loaded policies should list")
            .len(),
        corpus.policy_count
    );

    let read_request = request(TARGET_USER, None, "read");
    let read = engine
        .evaluate(&read_request)
        .expect("scale read request should evaluate");
    assert!(matches!(read, Decision::Allow { .. }));

    let delete_request = request(TARGET_USER, None, "delete");
    let delete = engine
        .evaluate_with_diagnostics(&delete_request)
        .expect("scale delete request should evaluate");
    assert!(matches!(delete.decision, Decision::Deny { .. }));
    assert_eq!(
        delete.matched_forbid_policy_ids,
        ["scale.target.delete_forbid"]
    );

    let review_request = request(
        TARGET_USER,
        Some(vec![REVIEWERS_GROUP.to_string()]),
        "review",
    );
    let review = engine
        .evaluate(&review_request)
        .expect("scale group request should evaluate");
    assert!(matches!(review, Decision::Allow { .. }));

    let no_match_request = request(TARGET_USER, None, "noise_00");
    let no_match = engine
        .evaluate(&no_match_request)
        .expect("scale no-match request should evaluate");
    assert!(matches!(no_match, Decision::Deny { .. }));

    let candidates = engine
        .list_policies(&read_request)
        .expect("scale policy listing should succeed");
    assert_eq!(candidates.policies().len(), 1);

    let version_before_reload = engine.current_version();
    let replacement = ScaleCorpus::new(policy_count, 1);
    let reload_started = Instant::now();
    engine
        .reload_from_str(&replacement.policy_text)
        .expect("replacement scale corpus should reload");
    let reload_elapsed = reload_started.elapsed();
    assert_ne!(version_before_reload.hash, engine.current_version().hash);
    assert!(matches!(
        engine
            .evaluate(&read_request)
            .expect("request should evaluate after scale reload"),
        Decision::Allow { .. }
    ));

    let version_before_failure = engine.current_version();
    assert!(engine.reload_from_str("permit (").is_err());
    assert_eq!(version_before_failure.hash, engine.current_version().hash);
    assert!(matches!(
        engine
            .evaluate(&read_request)
            .expect("failed scale reload should preserve the active snapshot"),
        Decision::Allow { .. }
    ));

    eprintln!(
        "policy scale: count={policy_count}, bytes={}, generate={generation_elapsed:?}, load={load_elapsed:?}, reload={reload_elapsed:?}",
        corpus.policy_text.len()
    );
}

#[test]
fn generated_corpus_is_deterministic_and_has_exact_policy_count() {
    let first = ScaleCorpus::new(128, 7);
    let second = ScaleCorpus::new(128, 7);
    let next_generation = ScaleCorpus::new(128, 8);

    assert_eq!(first.policy_text, second.policy_text);
    assert_eq!(first.schema_text, second.schema_text);
    assert_ne!(first.policy_text, next_generation.policy_text);

    let engine =
        PolicyEngine::new_from_str_with_cedarschema(&first.policy_text, &first.schema_text)
            .expect("small generated corpus should load");
    assert_eq!(engine.policies().unwrap().len(), first.policy_count);
}

#[test]
#[ignore = "exercised explicitly in CI with 10k policies and in scale CI with 100k+"]
fn configured_policy_scale_loads_evaluates_lists_and_reloads() {
    exercise_scale_corpus(configured_policy_count());
}

#[test]
fn pr_scale_configuration_remains_ten_thousand_policies() {
    assert_eq!(PR_SCALE_POLICY_COUNT, 10_000);
}
