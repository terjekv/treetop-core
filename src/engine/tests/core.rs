#[test]
fn test_current_version_hash() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
    let version = engine.current_version();

    let expected_hash = format!("{:x}", Sha256::digest(TEST_POLICY.as_bytes()));
    assert_eq!(version.hash, expected_hash);
}

#[test]
fn test_policysnapshot_policies() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
    let snapshot = engine.current_snapshot();
    let policies = snapshot.policy_set();
    assert_eq!(policies.policies().count(), 2);
}

#[test]
fn test_concurrent_evaluation() {
    use std::sync::Arc;
    use std::thread;

    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine = Arc::new(PolicyEngine::new_from_str(policies).unwrap());
    let mut handles = vec![];

    // Spawn 10 threads, each doing 100 evaluations
    for i in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let request = Request {
                    principal: Principal::User(User::new("alice", None, None)),
                    action: Action::new("read", None),
                    resource: Resource::new("Document", format!("doc{}", i % 5)),
                };
                let decision = engine_clone.evaluate(&request);
                assert!(decision.is_ok());
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_concurrent_label_registry_access() {
    use std::thread;

    let patterns = vec![("test_label".to_string(), Regex::new(r"test").unwrap())];
    let labeler = RegexLabeler::new("Host", "name", "nameLabels", patterns);

    let label_registry = Arc::new(
        LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler))
            .build(),
    );

    let mut handles = vec![];

    // Multiple threads applying labels
    for i in 0..5 {
        let registry = Arc::clone(&label_registry);
        let handle = thread::spawn(move || {
            let mut resource = Resource::new("Host", format!("test-{}", i))
                .with_attr("name", AttrValue::String(format!("test-{}", i)));

            registry.apply(&mut resource);

            // Verify labels were applied
            if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
                assert!(!labels.is_empty());
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_error_context_on_invalid_entity() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let _ = PolicyEngine::new_from_str(policies).unwrap();

    // Create request with malformed principal
    let result = "Invalid::Entity::Structure".parse::<EntityUid>();
    assert!(result.is_err());
}

#[test]
fn test_error_context_on_malformed_policy() {
    let malformed_policy = r#"
            permit (
                principal == User::"alice"
                // Missing comma and rest of policy
        "#;

    let result = PolicyEngine::new_from_str(malformed_policy);
    assert!(result.is_err());

    if let Err(PolicyError::ParseError(msg)) = result {
        assert!(msg.contains("parse") || msg.contains("expected"));
    } else {
        panic!("Expected ParseError");
    }
}

#[test]
fn test_empty_policy_text() {
    let result = PolicyEngine::new_from_str("");
    assert!(result.is_ok());

    let engine = result.unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc1"),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(matches!(decision, Decision::Deny { .. }));
}

#[test]
fn test_whitespace_only_policy() {
    let result = PolicyEngine::new_from_str("   \n\t  \n  ");
    assert!(result.is_ok());
}

#[test]
fn test_label_registry_initialization() {
    let patterns1 = vec![("label1".to_string(), Regex::new(r"test1").unwrap())];
    let labeler1 = RegexLabeler::new("Host", "name", "nameLabels", patterns1);

    let label_registry = LabelRegistryBuilder::new()
        .add_labeler(Arc::new(labeler1))
        .build();

    let mut resource = Resource::new("Host", "test1-host")
        .with_attr("name", AttrValue::String("test1-host".into()));

    label_registry.apply(&mut resource);

    if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
        assert_eq!(labels.len(), 1);
    }
}

#[test]
fn test_apply_labels_with_no_labelers() {
    // Test that an empty registry doesn't panic
    let label_registry = LabelRegistryBuilder::new().build();

    let mut resource =
        Resource::new("Host", "test-host").with_attr("name", AttrValue::String("test-host".into()));

    // Should not panic with no labelers
    label_registry.apply(&mut resource);

    // Verify no labels were added
    assert!(resource.attrs().get("nameLabels").is_none());
}

#[test]
fn test_label_registry_replacement() {
    let patterns1 = vec![("old_label".to_string(), Regex::new(r"old").unwrap())];
    let labeler1 = RegexLabeler::new("Host", "name", "nameLabels", patterns1);

    let label_registry = LabelRegistryBuilder::new()
        .add_labeler(Arc::new(labeler1))
        .build();

    let patterns2 = vec![("new_label".to_string(), Regex::new(r"new").unwrap())];
    let labeler2 = RegexLabeler::new("Host", "name", "nameLabels", patterns2);

    // Replace labelers via reload
    label_registry.reload(vec![Arc::new(labeler2)]);

    let mut resource =
        Resource::new("Host", "new-host").with_attr("name", AttrValue::String("new-host".into()));

    label_registry.apply(&mut resource);

    if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
        // Should have new_label, not old_label
        let has_new = labels.iter().any(|l| {
            if let AttrValue::String(s) = l {
                s == "new_label"
            } else {
                false
            }
        });
        assert!(has_new);
    }
}

#[test]
fn test_large_policy_set() {
    // Generate 100 policies
    let mut policies = String::new();
    for i in 0..100 {
        policies.push_str(&format!(
            r#"
                permit (
                    principal == User::"user{}",
                    action == Action::"read",
                    resource == Document::"doc{}"
                );
                "#,
            i, i
        ));
    }

    let engine = PolicyEngine::new_from_str(&policies).unwrap();

    // Test evaluation still works
    let request = Request {
        principal: Principal::User(User::new("user50", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc50"),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(matches!(decision, Decision::Allow { .. }));
}

#[test]
fn test_deeply_nested_namespaces() {
    let policies = r#"
            permit (
                principal == A::B::C::D::E::User::"alice",
                action == A::B::C::D::E::Action::"read",
                resource == A::B::C::D::E::Document::"doc1"
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    let request = Request {
        principal: Principal::User(User::new(
            "alice",
            None,
            Some(vec![
                "A".into(),
                "B".into(),
                "C".into(),
                "D".into(),
                "E".into(),
            ]),
        )),
        action: Action::new(
            "read",
            Some(vec![
                "A".into(),
                "B".into(),
                "C".into(),
                "D".into(),
                "E".into(),
            ]),
        ),
        resource: Resource::new("A::B::C::D::E::Document", "doc1"),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(matches!(decision, Decision::Allow { .. }));
}

#[test]
fn test_resource_with_many_attributes() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource is Document
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    // Create resource with 50 attributes
    let mut resource = Resource::new("Document", "doc1");
    for i in 0..50 {
        resource = resource.with_attr(
            format!("attr{}", i),
            AttrValue::String(format!("value{}", i)),
        );
    }

    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource,
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(matches!(decision, Decision::Allow { .. }));
}

#[test]
fn test_user_with_many_groups() {
    let policies = r#"
            permit (
                principal in Group::"group25",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    // Create user in 50 groups
    let groups: Vec<String> = (0..50).map(|i| format!("group{}", i)).collect();

    let request = Request {
        principal: Principal::User(User::new("alice", Some(groups), None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc1"),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(matches!(decision, Decision::Allow { .. }));
}

#[test]
fn test_decision_includes_correct_version() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();
    let engine_version = engine.current_version();

    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc1"),
    };

    let decision = engine.evaluate(&request).unwrap();

    match decision {
        Decision::Allow { version, .. } => {
            assert_eq!(version.hash, engine_version.hash);
        }
        Decision::Deny { .. } => panic!("Expected Allow"),
    }
}

#[test]
fn test_multiple_snapshots_share_data() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine1 = PolicyEngine::new_from_str(policies).unwrap();
    let engine2 = engine1.clone();

    let version1 = engine1.current_version();
    let version2 = engine2.current_version();

    // Both clones should share the same snapshot
    assert_eq!(version1.hash, version2.hash);
    assert_eq!(version1.loaded_at, version2.loaded_at);
}

#[test]
fn test_multiple_policies_captured() {
    // Test that when multiple policies match, all are captured in the Decision
    let policies = r#"
            permit (
                principal,
                action == Action::"read",
                resource == Document::"public"
            );

            permit (
                principal == User::"alice",
                action,
                resource
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    // Alice reading public document should match both policies
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "public"),
    };

    let decision = engine.evaluate(&request).unwrap();

    match decision {
        Decision::Allow { policies, .. } => {
            assert_eq!(
                policies.len(),
                2,
                "Should have captured both matching policies"
            );
            // Both policy0 and policy1 should be present
            let policy_ids: Vec<_> = policies.iter().map(|p| p.cedar_id.as_str()).collect();
            assert!(policy_ids.contains(&"policy0"), "Should contain policy0");
            assert!(policy_ids.contains(&"policy1"), "Should contain policy1");
        }
        Decision::Deny { .. } => panic!("Expected Allow decision"),
    }
}
