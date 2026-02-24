use super::*;

#[test]
fn test_schema_rejects_invalid_policy_at_load() {
    let invalid_policy = r#"
        permit (
            principal == User::"alice",
            action == Action::"write",
            resource is Document
        );
    "#;

    let result = PolicyEngine::new_from_str_with_cedarschema(invalid_policy, TEST_SCHEMA);
    assert!(matches!(result, Err(PolicyError::ParseError(_))));
}

#[test]
fn test_schema_object_constructor_works() {
    let schema: Schema = TEST_SCHEMA.parse().unwrap();
    let engine = PolicyEngine::new_from_str_with_schema(TEST_SCHEMA_POLICY, schema)
        .expect("schema + policy should load");
    let request = user_request("alice", "read", document_with_sensitivity("doc1", 1));

    let decision = engine.evaluate(&request).unwrap();
    assert_allow(&decision);
}

#[test]
fn test_schema_text_constructor_rejects_invalid_schema() {
    let result = PolicyEngine::new_from_str_with_cedarschema(
        TEST_SCHEMA_POLICY,
        "this is not valid cedar schema",
    );
    assert!(matches!(result, Err(PolicyError::ParseError(_))));
}

#[test]
fn test_schema_validates_request_principal_type() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);

    let request = group_request("admins", "read", document_with_sensitivity("doc1", 1));

    let result = engine.evaluate(&request);
    assert!(matches!(
        result,
        Err(PolicyError::RequestValidationError(_))
    ));
}

#[test]
fn test_schema_validates_entity_attribute_types() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);

    let request = user_request(
        "alice",
        "read",
        Resource::new("Document", "doc1")
            .with_attr("sensitivity", AttrValue::String("high".into())),
    );

    let result = engine.evaluate(&request);
    assert!(matches!(result, Err(PolicyError::EntityError(_))));
}

#[test]
fn test_schema_rejects_unknown_action_in_request() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);

    let request = user_request("alice", "delete", document_with_sensitivity("doc1", 1));

    let result = engine.evaluate(&request);
    assert!(matches!(
        result,
        Err(PolicyError::RequestValidationError(_))
    ));
}

#[test]
fn test_reload_preserves_schema_validation() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);
    let invalid_policy = r#"
        permit (
            principal == User::"alice",
            action == Action::"write",
            resource is Document
        );
    "#;

    let result = engine.reload_from_str(invalid_policy);
    assert!(matches!(result, Err(PolicyError::ParseError(_))));
}

#[test]
fn test_reload_with_schema_object_changes_enforcement() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);

    let read_request = user_request("alice", "read", document_with_sensitivity("doc1", 1));
    let read_before_reload = engine.evaluate(&read_request).unwrap();
    assert_allow(&read_before_reload);

    let schema_write: Schema = TEST_SCHEMA_WRITE.parse().unwrap();
    engine
        .reload_from_str_with_schema(TEST_SCHEMA_POLICY_WRITE, schema_write)
        .unwrap();

    let write_request = user_request("alice", "write", document_with_sensitivity("doc1", 1));
    let write_after_reload = engine.evaluate(&write_request).unwrap();
    assert_allow(&write_after_reload);

    let read_after_reload = engine.evaluate(&read_request);
    assert!(matches!(
        read_after_reload,
        Err(PolicyError::RequestValidationError(_))
    ));
}

#[test]
fn test_reload_with_schema_text_rejects_invalid_schema() {
    let engine = engine_from_policy(TEST_SCHEMA_POLICY);
    let result = engine
        .reload_from_str_with_cedarschema(TEST_SCHEMA_POLICY, "this is not valid cedar schema");
    assert!(matches!(result, Err(PolicyError::ParseError(_))));
}

#[test]
fn test_reload_with_schema_object_failure_is_atomic() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);
    let read_request = user_request("alice", "read", document_with_sensitivity("doc1", 1));
    let version_before = engine.current_version();

    let decision_before = engine.evaluate(&read_request).unwrap();
    assert_allow(&decision_before);

    let schema_write: Schema = TEST_SCHEMA_WRITE.parse().unwrap();
    let result = engine.reload_from_str_with_schema(TEST_SCHEMA_POLICY, schema_write);
    assert!(matches!(result, Err(PolicyError::ParseError(_))));

    let version_after = engine.current_version();
    assert_eq!(version_before.hash, version_after.hash);
    assert_eq!(version_before.loaded_at, version_after.loaded_at);

    let decision_after = engine.evaluate(&read_request).unwrap();
    assert_allow(&decision_after);
}

#[test]
fn test_reload_with_schema_text_failure_is_atomic() {
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);
    let read_request = user_request("alice", "read", document_with_sensitivity("doc1", 1));
    let version_before = engine.current_version();

    let decision_before = engine.evaluate(&read_request).unwrap();
    assert_allow(&decision_before);

    let invalid_policy = r#"
        permit (
            principal == User::"alice",
            action == Action::"write",
            resource is Document
        );
    "#;
    let result = engine.reload_from_str_with_cedarschema(invalid_policy, TEST_SCHEMA);
    assert!(matches!(result, Err(PolicyError::ParseError(_))));

    let version_after = engine.current_version();
    assert_eq!(version_before.hash, version_after.hash);
    assert_eq!(version_before.loaded_at, version_after.loaded_at);

    let decision_after = engine.evaluate(&read_request).unwrap();
    assert_allow(&decision_after);
}

#[test]
fn test_non_schema_engine_can_reload_with_schema() {
    let engine = engine_from_policy(TEST_SCHEMA_POLICY_WRITE);
    let write_without_schema = user_request("alice", "write", Resource::new("Document", "doc1"));

    let decision_before = engine.evaluate(&write_without_schema).unwrap();
    assert_allow(&decision_before);

    engine
        .reload_from_str_with_cedarschema(TEST_SCHEMA_POLICY, TEST_SCHEMA)
        .unwrap();

    let read_with_schema = user_request("alice", "read", document_with_sensitivity("doc1", 1));
    let decision_after = engine.evaluate(&read_with_schema).unwrap();
    assert_allow(&decision_after);

    let write_after = user_request("alice", "write", document_with_sensitivity("doc1", 1));
    let result = engine.evaluate(&write_after);
    assert!(matches!(
        result,
        Err(PolicyError::RequestValidationError(_))
    ));
}

#[test]
#[serial_test::serial]
fn test_reload_logs_schema_status() {
    use std::sync::OnceLock;

    static LOG_SINK: OnceLock<SharedLogBuffer> = OnceLock::new();
    let sink = LOG_SINK
        .get_or_init(|| {
            let sink = SharedLogBuffer(Arc::new(std::sync::Mutex::new(Vec::new())));
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .without_time()
                .with_target(false)
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(sink.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("global test subscriber should initialize");
            tracing::callsite::rebuild_interest_cache();
            sink
        })
        .clone();

    sink.0.lock().unwrap().clear();
    let engine = schema_engine_from_policy(TEST_SCHEMA_POLICY, TEST_SCHEMA);

    let schema_write: Schema = TEST_SCHEMA_WRITE.parse().unwrap();
    engine
        .reload_from_str_with_schema(TEST_SCHEMA_POLICY_WRITE, schema_write)
        .unwrap();

    let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("PolicyReload"),
        "expected schema reload log event, logs: {logs}"
    );
    assert!(
        logs.contains("schema_reloaded=true") || logs.contains("schema_reloaded: true"),
        "expected schema_reloaded=true in logs: {logs}"
    );
}

#[test]
fn test_non_schema_engine_behavior_unchanged() {
    let policy_not_allowed_by_test_schema = r#"
        permit (
            principal == User::"alice",
            action == Action::"write",
            resource is Document
        );
    "#;

    // This should remain valid when no schema is configured.
    let engine = engine_from_policy(policy_not_allowed_by_test_schema);
    let request = user_request("alice", "write", Resource::new("Document", "doc1"));

    let decision = engine.evaluate(&request).unwrap();
    assert_allow(&decision);
}
