#[parameterized(
        alice_edit_allow = { "alice", "edit", "VacationPhoto94.jpg" },
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg" },
        alice_delete_allow = { "alice", "delete", "VacationPhoto94.jpg" },
        alice_view_deny_wrong_photo = { "alice", "view", "wrongphoto.jpg" },
        bob_view_allow = { "bob", "view", "VacationPhoto94.jpg" },
        bob_edit_deny = { "bob", "edit", "VacationPhoto94.jpg", },
        bob_view_deny_wrong_photo = { "bob", "edit", "wrongphoto.jpg", },
        charlie_view_deny = { "charlie", "view", "VacationPhoto94.jpg", },
    )]
fn test_evaluate_requests(user: &str, action: &str, resource: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();

    // Convert the resource to the appropriate type
    let resource = Resource::new("Photo", resource.to_string())
        .with_attr("name", AttrValue::String(resource.to_string()));

    let request = Request {
        principal: Principal::User(User::new(user, None, None)),
        action: Action::new(action, None),
        resource,
    };
    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_create_host_allow = { "alice", "create_host", "web-01.example.com", "192.0.1.1" },
        bob_create_host_allow = { "bob", "create_host", "bob-01.example.com", "192.0.0.1" },
        alice_create_host_wrong_net_deny = { "alice", "create_host", "web-99.example.com", "192.0.2.1" },
        alice_create_host_wrong_name_deny = { "alice", "create_host", "abc.example.com", "192.0.1.2" },
    )]
fn test_create_host_requests(user: &str, action: &str, host_name: &str, ip: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_CONTEXT).unwrap();

    let request = Request {
        principal: Principal::User(User::new(user, None, None)),
        action: Action::new(action, None),
        resource: Resource::new("Host", host_name)
            .with_attr("name", AttrValue::String(host_name.into()))
            .with_attr("ip", AttrValue::Ip(ip.into())),
    };
    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg" },
        alice_edit_deny_explicit = { "alice", "edit", "VacationPhoto94.jpg" },
        alice_delete_forbid_any = { "alice", "delete", "VacationPhoto94.jpg" },
    )]
fn test_policy_with_forbid(user: &str, action: &str, resource: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();

    // Convert the resource to the appropriate type
    let resource = Resource::new("Photo", resource.to_string())
        .with_attr("name", AttrValue::String(resource.to_string()));

    let request = Request {
        principal: Principal::User(User::new(user, None, None)),
        action: Action::new(action, None),
        resource,
    };
    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_web_and_example_allow = { "alice", "web-01.example.com" },
        alice_no_web_allow = { "alice", "flappa.example.com" },
        alice_only_example_allow = { "alice", "whatever.example.com" },
        alice_no_example_deny = { "alice", "web.examples.com" },
        bob_web_and_example_allow = { "bob", "web-01.example.com" },
        bob_host_pattern_no_web_deny = { "bob", "somehost.example.com" },
        bob_host_pattern_no_example_deny = { "bob", "example.com" },

    )]
fn test_policy_with_host_patterns(username: &str, host_name: &str) {
    let patterns = vec![
        ("valid_web_name".to_string(), Regex::new(r"^web.*").unwrap()),
        (
            "example_domain".to_string(),
            Regex::new(r"example\.com$").unwrap(),
        ),
    ];
    let labeler = RegexLabeler::new("Host", "name", "nameLabels", patterns.into_iter().collect());

    let label_registry = LabelRegistryBuilder::new()
        .add_labeler(Arc::new(labeler))
        .build();

    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_HOST_PATTERNS)
        .unwrap()
        .with_label_registry(label_registry);

    let request = Request {
        principal: Principal::User(User::new(username, None, None)),
        action: Action::new("create_host", None),
        resource: Resource::new("Host", host_name.to_string())
            .with_attr("name", AttrValue::String(host_name.into()))
            .with_attr("ip", AttrValue::Ip("10.0.0.1".into())),
    };

    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_allow = {"alice" },
        bob_deny = {"bob" }
    )]
fn test_only_here_policy(username: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_ACTION_ONLY_HERE).unwrap();
    let request = Request {
        principal: Principal::User(User::new(username, None, None)),
        action: Action::new("only_here", None),
        resource: Resource::new("Photo", "irrelevant_photo.jpg")
            .with_attr("name", AttrValue::String("irrelevant.example.com".into()))
            .with_attr("ip", AttrValue::Ip("10.0.0.1".into())),
    };

    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_assign_gateway_allow = { "alice", "assign_gateway", "mygateway" },
        bob_assign_gateway_deny = { "bob", "assign_gateway", "mygateway" },
        alice_assign_gateway_wrong_id_deny = { "alice", "assign_gateway", "wronggateway" },
    )]
fn test_generic_policies(user: &str, action: &str, resource_id: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_GENERIC_RESOURCE).unwrap();
    let request = Request {
        principal: Principal::User(User::new(user, None, None)),
        action: Action::new(action, None),
        resource: Resource::new("Gateway", resource_id.to_string()),
    };
    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_delete_allow = { "alice", "admins", "delete" },
        alice_view_allow = { "alice", "admins", "view" },
        bob_delete_deny = { "bob", "users", "delete" },
        bob_view_allow = { "bob", "users", "view" },
    )]
fn test_policy_with_groups(user: &str, group: &str, action: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

    // Convert the resource to the appropriate type
    let resource = Resource::new("Photo", "photo.jpg".to_string());

    let request = Request {
        principal: Principal::User(User::new(user, Some(vec![group.to_string()]), None)),
        action: Action::new(action, None),
        resource,
    };
    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        admins_delete_allow = { "admins", "delete" },
        admins_view_allow = { "admins", "view" },
        users_view_allow = { "users", "view" },
        users_delete_deny = { "users", "delete" },
    )]
fn test_group_direct_access(group: &str, action: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

    // Convert the resource to the appropriate type
    let resource = Resource::new("Photo", "photo.jpg".to_string());

    let request = Request {
        principal: Principal::Group(Group::new(group, None)),
        action: Action::new(action, None),
        resource,
    };

    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[test]
fn test_policy_by_id() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_BY_ID).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", Some(vec!["admins".to_string()]), None)),
        action: Action::new("view", None),
        resource: Resource::new("Photo", "VacationPhoto94.jpg".to_string()),
    };
    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_namespace_database_create_allow = { "alice", "create_table", "dbusers", "Database" },
        bob_namespace_database_create_deny = { "bob", "create_table", "dbusers", "Database" },
        bob_namespace_database_view_allow = { "bob", "view_table", "dbusers", "Database" },
        bob_namespace_furniture_allow = { "bob", "create_table", "carpenters", "Furniture" },
        alice_namespace_furniture_deny = { "alice", "create_table", "spectators", "Furniture" },

    )]
fn test_namespaces(user: &str, action: &str, group: &str, namespace: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();
    let request = Request {
        principal: Principal::User(User::new(
            user,
            Some(vec![group.to_string()]),
            Some(vec![namespace.to_string()]),
        )),
        action: Action::new(action, Some(vec![namespace.to_string()])),
        resource: Resource::new(format!("{}::{}", namespace, "Table"), "mytable".to_string()),
    };

    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_ip_allow_1 = { "192.168.0.1" },
        alice_ip_allow_255 = { "192.168.0.255" },
        alice_ip_deny_wrong_net = { "10.0.0.1" },
        alice_ip_allow_same_network = { "192.168.0.0/24" }, // The same network is OK
        alice_ip_deny_largernetwork = { "192.168.0.0/23" }, // A larger network is NOT OK
        alice_ip_allow_subnet_of_network = { "192.168.0.0/25" } // A smaller subnet is OK


    )]
fn test_ip_functionality(ip: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IP).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("create_host", None),
        resource: Resource::new("Host", "host.example.com".to_string())
            .with_attr("ip", AttrValue::Ip(ip.to_string())),
    };

    let decision = engine.evaluate(&request).unwrap();
    snapshot_decision_engine!(decision);
}

#[parameterized(
        alice_ip_err_not_ip = { "not.an.ip.address" },
        alice_ip_err_empty = { "" },
    )]
fn test_ip_functionality_errors(ip: &str) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IP).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("create_host", None),
        resource: Resource::new("Host", "host.example.com".to_string())
            .with_attr("ip", AttrValue::Ip(ip.to_string())),
    };

    assert!(engine.evaluate(&request).is_err());
}

#[test]
fn test_evaluate_with_context_supports_context_conditions() {
    let policy = r#"
permit (
    principal == User::"alice",
    action == Action::"deploy",
    resource == Service::"backend"
) when {
    context.env == "prod" && context.ticket > 1000
};
"#;
    let engine = PolicyEngine::new_from_str(policy).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("deploy", None),
        resource: Resource::new("Service", "backend"),
    };

    let without_context = engine.evaluate(&request).unwrap();
    assert!(matches!(without_context, Deny { .. }));

    let context = RequestContext::new()
        .with_attr("env", AttrValue::String("prod".to_string()))
        .with_attr("ticket", AttrValue::Long(1337));
    let with_context = engine.evaluate_with_context(&request, &context).unwrap();
    assert!(matches!(with_context, Allow { .. }));
}

#[test]
fn test_evaluate_with_diagnostics_reports_forbid_ids() {
    let policy = r#"
@id("allow_alice_read")
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"doc1"
);
@id("deny_alice_read")
forbid (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"doc1"
);
"#;
    let engine = PolicyEngine::new_from_str(policy).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Document", "doc1"),
    };

    let diagnostics = engine.evaluate_with_diagnostics(&request).unwrap();
    assert!(matches!(diagnostics.decision, Deny { .. }));
    assert_eq!(
        diagnostics.matched_forbid_policy_ids,
        vec!["deny_alice_read".to_string()]
    );
}
