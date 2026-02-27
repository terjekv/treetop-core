use super::*;

#[test]
fn test_reload_policy() {
    let engine = engine_from_policy(TEST_POLICY);
    let request = user_request(
        "bob",
        "view",
        Resource::from_str("Photo::VacationPhoto94.jpg").unwrap(),
    );

    let before_reload = engine.evaluate(&request).unwrap();
    assert_allow(&before_reload);

    engine.reload_from_str(TEST_POLICY_WITHOUT_BOB).unwrap();

    let after_reload = engine.evaluate(&request).unwrap();
    assert_deny(&after_reload);
}

#[test]
fn test_policy_reload_during_evaluation() {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let initial_policy = r#"
        permit (
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"doc1"
        );
    "#;

    let updated_policy = r#"
        permit (
            principal == User::"bob",
            action == Action::"write",
            resource == Document::"doc2"
        );
    "#;

    let engine = Arc::new(engine_from_policy(initial_policy));
    let engine_eval = Arc::clone(&engine);
    let engine_reload = Arc::clone(&engine);

    // Thread 1: Continuously evaluate
    let eval_handle = thread::spawn(move || {
        for _ in 0..100 {
            let request = Request {
                principal: Principal::User(User::new("alice", None, None)),
                action: Action::new("read", None),
                resource: Resource::new("Document", "doc1"),
            };
            let _ = engine_eval.evaluate(&request);
            thread::sleep(Duration::from_micros(10));
        }
    });

    // Thread 2: Reload policies
    let reload_handle = thread::spawn(move || {
        for _ in 0..10 {
            let _ = engine_reload.reload_from_str(updated_policy);
            thread::sleep(Duration::from_millis(1));
        }
    });

    eval_handle.join().unwrap();
    reload_handle.join().unwrap();
}

#[test]
fn test_policy_version_changes_on_reload() {
    let policy1 = r#"
        permit (
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"doc1"
        );
    "#;

    let policy2 = r#"
        permit (
            principal == User::"bob",
            action == Action::"write",
            resource == Document::"doc2"
        );
    "#;

    let engine = engine_from_policy(policy1);
    let version1 = engine.current_version();

    engine.reload_from_str(policy2).unwrap();
    let version2 = engine.current_version();

    assert_ne!(version1.hash, version2.hash);
    assert_ne!(version1.loaded_at, version2.loaded_at);
}

#[test]
fn test_snapshot_immutable_after_reload() {
    let policy1 = r#"
        permit (
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"doc1"
        );
    "#;

    let policy2 = r#"
        permit (
            principal == User::"bob",
            action == Action::"write",
            resource == Document::"doc2"
        );
    "#;

    let engine = engine_from_policy(policy1);
    let snapshot1 = engine.current_snapshot();
    let version1 = snapshot1.version();

    engine.reload_from_str(policy2).unwrap();

    // Old snapshot should still have old version
    let still_version1 = snapshot1.version();
    assert_eq!(version1.hash, still_version1.hash);

    // New snapshot should have new version
    let snapshot2 = engine.current_snapshot();
    let version2 = snapshot2.version();
    assert_ne!(version1.hash, version2.hash);
}

#[test]
fn test_reload_failure_preserves_snapshot_and_behavior() {
    let engine = engine_from_policy(TEST_POLICY);
    let request = user_request(
        "bob",
        "view",
        Resource::from_str("Photo::VacationPhoto94.jpg").unwrap(),
    );
    let version_before = engine.current_version();

    let decision_before = engine.evaluate(&request).unwrap();
    assert_allow(&decision_before);

    let malformed_policy = r#"
        permit (
            principal == User::"bob"
            // missing comma and remaining fields
    "#;
    let result = engine.reload_from_str(malformed_policy);
    assert!(matches!(result, Err(PolicyError::ParseError(_))));

    let version_after = engine.current_version();
    assert_eq!(version_before.hash, version_after.hash);
    assert_eq!(version_before.loaded_at, version_after.loaded_at);

    let decision_after = engine.evaluate(&request).unwrap();
    assert_allow(&decision_after);
}
