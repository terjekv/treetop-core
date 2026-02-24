#[parameterized(
        alice_permissions = { "alice", vec![], 2, vec!["create_host", "delete", "edit", "view"] },
        bob_permissions = { "bob", vec![], 1, vec!["view"] },
        charlie_permissions = { "charlie", vec![], 0, vec![] },
    )]
fn test_list_permissions(
    user: &str,
    groups: Vec<String>,
    expected_policies: usize,
    expected_actions: Vec<&str>,
) {
    let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();

    let group_strs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let user_policies = engine
        .list_policies_for_user(user, &group_strs, &[])
        .expect("Failed to list permissions");
    assert_eq!(user_policies.policies().len(), expected_policies);

    // Fetch the actions by name, this list is automatically sorted
    let actions = user_policies.actions_by_name();

    assert_eq!(actions.len(), expected_actions.len());

    for (i, action) in expected_actions.iter().enumerate() {
        let padded_action = format!("Action::\"{}\"", action);
        assert_eq!(padded_action, actions[i].to_string(),);
    }
}

// So, the arrays in the serialized output are not guaranteed to be in the same order,
// even with sort-maps set to true for insta. As such, we end up needing to do this
// rather manually.
#[test]
fn test_serialize_user_permissions() {
    let combined = TEST_PERMISSION_POLICY.to_string() + TEST_POLICY_WITH_CONTEXT;
    let engine = PolicyEngine::new_from_str(&combined).unwrap();

    let perms = engine.list_policies_for_user("alice", &[], &[]).unwrap();

    let expected_serialized = r#"{"user":"alice","policies":[{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"in","entities":[{"type":"Action","id":"view"},{"type":"Action","id":"edit"},{"type":"Action","id":"delete"}]},"resource":{"op":"==","entity":{"type":"Photo","id":"VacationPhoto94.jpg"}},"conditions":[]},{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"==","entity":{"type":"Action","id":"create_host"}},"resource":{"op":"is","entity_type":"Host"},"conditions":[]},{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"==","entity":{"type":"Action","id":"create_host"}},"resource":{"op":"is","entity_type":"Host"},"conditions":[{"kind":"when","body":{"&&":{"left":{"like":{"left":{".":{"left":{"Var":"resource"},"attr":"name"}},"pattern":[{"Literal":"w"},{"Literal":"e"},{"Literal":"b"},"Wildcard"]}},"right":{"isInRange":[{".":{"left":{"Var":"resource"},"attr":"ip"}},{"ip":[{"Value":"192.0.1.0/24"}]}]}}}}]}]}"#;

    let actual: serde_json::Value = serde_json::to_value(&perms).unwrap();
    let expected: serde_json::Value = serde_json::from_str(expected_serialized).unwrap();

    assert_eq!(actual["user"], expected["user"]);

    let act_arr = actual["policies"].as_array().unwrap();
    let exp_arr = expected["policies"].as_array().unwrap();
    assert_eq!(act_arr.len(), exp_arr.len(), "wrong number of policies");

    for exp in exp_arr {
        assert!(
            act_arr.iter().any(|act| act == exp),
            "expected policy not found: {:#}",
            exp
        );
    }
}

#[parameterized(
        admins_can_view_delete = { "admin_user", vec!["admins".to_string()], 1, vec!["delete", "view"] },
        users_can_only_view = { "regular_user", vec!["users".to_string()], 1, vec!["view"] },
        both_groups = { "super_user", vec!["admins".to_string(), "users".to_string()], 2, vec!["delete", "view", "view"] },
        no_groups = { "bob", vec![], 0, vec![] },
    )]
fn test_list_policies_with_groups(
    user: &str,
    groups: Vec<String>,
    expected_policies: usize,
    expected_actions: Vec<&str>,
) {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

    let group_strs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let user_policies = engine
        .list_policies_for_user(user, &group_strs, &[])
        .expect("Failed to list policies");
    assert_eq!(
        user_policies.policies().len(),
        expected_policies,
        "Expected {} policies but got {}",
        expected_policies,
        user_policies.policies().len()
    );

    let actions = user_policies.actions_by_name();
    assert_eq!(
        actions.len(),
        expected_actions.len(),
        "Expected {} actions but got {}",
        expected_actions.len(),
        actions.len()
    );

    for (i, action) in expected_actions.iter().enumerate() {
        let padded_action = format!("Action::\"{}\"", action);
        assert_eq!(padded_action, actions[i].to_string());
    }
}

#[test]
fn test_list_policies_with_namespaces() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();

    // Test Database::User::"alice" with Database::Group::"dbusers"
    let user_policies = engine
        .list_policies_for_user("alice", &["dbusers"], &["Database"])
        .expect("Failed to list policies");

    // Should match both:
    // 1. principal == Database::User::"alice" (direct match)
    // 2. principal in Database::Group::"dbusers" (group membership)
    assert_eq!(user_policies.policies().len(), 2);
}

#[test]
fn test_list_policies_with_multiple_namespaces() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();

    // Test Furniture::Group::"carpenters"
    let user_policies = engine
        .list_policies_for_user("carpenter_user", &["carpenters"], &["Furniture"])
        .expect("Failed to list policies");

    // Should match principal in Furniture::Group::"carpenters"
    assert_eq!(user_policies.policies().len(), 1);
}

#[test]
fn test_list_policies_unconstrained_principal() {
    let policy_with_unconstrained_principal = r#"
permit (
    principal,
    action == Action::"view",
    resource
);
"#;
    let engine = PolicyEngine::new_from_str(policy_with_unconstrained_principal).unwrap();

    let user_policies = engine
        .list_policies_for_user("anyone", &[], &[])
        .expect("Failed to list policies");

    // The policy has unconstrained principal, so it should match any user
    assert_eq!(user_policies.policies().len(), 1);
}

#[test]
fn test_list_policies_no_matching_policies() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();

    let user_policies = engine
        .list_policies_for_user("charlie", &[], &[])
        .expect("Failed to list policies");

    // charlie is not mentioned in the policies
    assert_eq!(user_policies.policies().len(), 0);
}

#[test]
fn test_list_policies_basic() {
    // Basic list_policies_for_user usage
    let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();

    let user_policies = engine
        .list_policies_for_user("alice", &[], &[])
        .expect("Failed to list permissions");

    // Should have 2 policies for alice (one with exact match, one with generic action)
    assert_eq!(user_policies.policies().len(), 2);
}

#[test]
fn test_list_policies_with_is_and_isin() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IS_AND_ISIN).unwrap();

    let user_policies = engine
        .list_policies_for_user("alice", &["admins"], &[])
        .expect("Failed to list permissions");

    assert_eq!(user_policies.policies().len(), 2);

    let mut has_principal_is = false;
    let mut has_principal_is_in = false;
    for policy_match in user_policies.matches() {
        has_principal_is |= policy_match
            .reasons
            .contains(&PolicyMatchReason::PrincipalIs);
        has_principal_is_in |= policy_match
            .reasons
            .contains(&PolicyMatchReason::PrincipalIsIn);
    }

    assert!(has_principal_is);
    assert!(has_principal_is_in);
}

#[test]
fn test_list_policies_for_group_with_is_and_isin() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IS_AND_ISIN).unwrap();

    let group_policies = engine
        .list_policies_for_group("admins", &[])
        .expect("Failed to list group policies");

    assert_eq!(group_policies.policies().len(), 2);

    let reasons = group_policies
        .matches()
        .iter()
        .flat_map(|m| m.reasons.iter().cloned())
        .collect::<Vec<_>>();
    assert!(reasons.contains(&PolicyMatchReason::PrincipalIs));
    assert!(reasons.contains(&PolicyMatchReason::PrincipalIsIn));
}

#[test]
fn test_list_policies_with_optional_resource_constraints() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_RESOURCE_CONSTRAINTS).unwrap();

    let without_resource = engine
        .list_policies_for_user("alice", &[], &[])
        .expect("Failed listing policies");
    assert_eq!(without_resource.policies().len(), 3);

    let photo = Resource::new("Photo", "vacation.jpg");
    let with_photo = engine
        .list_policies_for_user_with_resource("alice", &[], &[], Some(&photo))
        .expect("Failed listing policies with resource");
    assert_eq!(with_photo.policies().len(), 2);

    let host = Resource::new("Host", "web-01");
    let with_host = engine
        .list_policies_for_user_with_resource("alice", &[], &[], Some(&host))
        .expect("Failed listing policies with host resource");
    assert_eq!(with_host.policies().len(), 1);

    let reasons = with_photo
        .matches()
        .iter()
        .flat_map(|m| m.reasons.iter().cloned())
        .collect::<Vec<_>>();
    assert!(reasons.contains(&PolicyMatchReason::ResourceIs));
    assert!(reasons.contains(&PolicyMatchReason::ResourceEq));
}

#[test]
fn test_group_membership_is_evaluated_per_request_and_per_listing_call() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

    // Same user, no groups: should not match group-based policies.
    let no_group_request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("view", None),
        resource: Resource::new("Photo", "photo.jpg"),
    };
    assert!(matches!(
        engine.evaluate(&no_group_request).unwrap(),
        Deny { .. }
    ));

    // Same user, with users group: now group policy should match.
    let users_group_request = Request {
        principal: Principal::User(User::new("alice", Some(vec!["users".into()]), None)),
        action: Action::new("view", None),
        resource: Resource::new("Photo", "photo.jpg"),
    };
    assert!(matches!(
        engine.evaluate(&users_group_request).unwrap(),
        Allow { .. }
    ));

    // Same engine + same user id for listing, but different group input:
    // group membership is taken from call input, not cached globally.
    let listed_without_groups = engine.list_policies_for_user("alice", &[], &[]).unwrap();
    let listed_with_users = engine
        .list_policies_for_user("alice", &["users"], &[])
        .unwrap();

    assert_eq!(listed_without_groups.policies().len(), 0);
    assert_eq!(listed_with_users.policies().len(), 1);
    assert!(
        listed_with_users
            .matches()
            .iter()
            .any(|m| m.reasons.contains(&PolicyMatchReason::PrincipalIn))
    );
}

#[test]
fn test_list_policies_mirrors_evaluate_input_shape() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", Some(vec!["admins".into()]), None)),
        action: Action::new("view", None),
        resource: Resource::new("Photo", "photo.jpg"),
    };

    let listed = engine.list_policies(&request).unwrap();
    assert_eq!(listed.policies().len(), 1);
    assert!(
        listed
            .matches()
            .iter()
            .all(|m| m.reasons.contains(&PolicyMatchReason::PrincipalIn))
    );
    assert!(
        listed
            .matches()
            .iter()
            .all(|m| m.reasons.contains(&PolicyMatchReason::ActionIn))
    );
    assert!(
        listed
            .matches()
            .iter()
            .all(|m| m.reasons.contains(&PolicyMatchReason::ResourceIs))
    );
}

#[test]
fn test_list_policies_output_is_deterministic() {
    let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();
    let first = engine.list_policies_for_user("alice", &[], &[]).unwrap();
    let second = engine.list_policies_for_user("alice", &[], &[]).unwrap();

    let first_ids = first
        .matches()
        .iter()
        .map(|m| m.cedar_id.clone())
        .collect::<Vec<_>>();
    let second_ids = second
        .matches()
        .iter()
        .map(|m| m.cedar_id.clone())
        .collect::<Vec<_>>();

    assert_eq!(first_ids, second_ids);
}

#[test]
fn test_list_policies_effect_filter_defaults_to_any_and_can_filter() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg");

    // Default API includes both permit and forbid (Any).
    let default_any = engine
        .list_policies_for_user_with_resource("alice", &[], &[], Some(&resource))
        .unwrap();
    assert_eq!(default_any.policies().len(), 3);

    let permit_only = engine
        .list_policies_for_user_with_resource_and_effect(
            "alice",
            &[],
            &[],
            Some(&resource),
            PolicyEffectFilter::Permit,
        )
        .unwrap();
    assert_eq!(permit_only.policies().len(), 1);
    assert!(
        permit_only
            .policies()
            .iter()
            .all(|policy| policy.effect() == cedar_policy::Effect::Permit)
    );

    let forbid_only = engine
        .list_policies_for_user_with_resource_and_effect(
            "alice",
            &[],
            &[],
            Some(&resource),
            PolicyEffectFilter::Forbid,
        )
        .unwrap();
    assert_eq!(forbid_only.policies().len(), 2);
    assert!(
        forbid_only
            .policies()
            .iter()
            .all(|policy| policy.effect() == cedar_policy::Effect::Forbid)
    );
}

#[test]
fn test_list_policies_with_effect_consistent_with_evaluate_on_forbid_deny() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("edit", None),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(matches!(decision, Deny { .. }));

    let any = engine.list_policies(&request).unwrap();
    let permit = engine
        .list_policies_with_effect(&request, PolicyEffectFilter::Permit)
        .unwrap();
    let forbid = engine
        .list_policies_with_effect(&request, PolicyEffectFilter::Forbid)
        .unwrap();

    // Request-based listing applies action constraints, so only the matching
    // forbid policy is returned for this action.
    assert_eq!(any.policies().len(), 2);
    assert_eq!(permit.policies().len(), 1);
    assert_eq!(forbid.policies().len(), 1);
}

#[test]
fn test_list_policies_for_group_with_effect_filter() {
    let policy = r#"
permit (
    principal in Group::"admins",
    action == Action::"view",
    resource is Photo
);
forbid (
    principal in Group::"admins",
    action == Action::"delete",
    resource is Photo
);
"#;
    let engine = PolicyEngine::new_from_str(policy).unwrap();
    let resource = Resource::new("Photo", "photo.jpg");

    let any = engine
        .list_policies_for_group_with_resource("admins", &[], Some(&resource))
        .unwrap();
    let permit = engine
        .list_policies_for_group_with_resource_and_effect(
            "admins",
            &[],
            Some(&resource),
            PolicyEffectFilter::Permit,
        )
        .unwrap();
    let forbid = engine
        .list_policies_for_group_with_resource_and_effect(
            "admins",
            &[],
            Some(&resource),
            PolicyEffectFilter::Forbid,
        )
        .unwrap();

    assert_eq!(any.policies().len(), 2);
    assert_eq!(permit.policies().len(), 1);
    assert_eq!(forbid.policies().len(), 1);
}

#[test]
fn test_list_policies_request_filters_on_action_constraint() {
    let policy = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"p"
);
permit (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"p"
);
"#;
    let engine = PolicyEngine::new_from_str(policy).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("view", None),
        resource: Resource::new("Photo", "p"),
    };

    let listed = engine.list_policies(&request).unwrap();
    assert_eq!(listed.policies().len(), 1);
    assert!(
        listed
            .matches()
            .iter()
            .all(|m| m.reasons.contains(&PolicyMatchReason::ActionEq))
    );
}

#[test]
fn test_list_policies_request_with_deep_namespace() {
    let policy = r#"
permit (
    principal in A::B::C::Group::"admins",
    action == A::B::C::Action::"view",
    resource is A::B::C::Photo
);
"#;
    let engine = PolicyEngine::new_from_str(policy).unwrap();
    let request = Request {
        principal: Principal::User(User::new(
            "alice",
            Some(vec!["admins".into()]),
            Some(vec!["A".into(), "B".into(), "C".into()]),
        )),
        action: Action::new("view", Some(vec!["A".into(), "B".into(), "C".into()])),
        resource: Resource::new("A::B::C::Photo", "holiday-1"),
    };

    assert!(matches!(engine.evaluate(&request).unwrap(), Allow { .. }));
    let listed = engine.list_policies(&request).unwrap();
    assert_eq!(listed.policies().len(), 1);
}

#[test]
fn test_list_policies_mixed_effect_order_is_deterministic() {
    let policy = r#"
@id("p3")
permit (principal == User::"alice", action == Action::"read", resource == Photo::"p");
@id("f1")
forbid (principal == User::"alice", action == Action::"read", resource == Photo::"p");
@id("p2")
permit (principal == User::"alice", action == Action::"read", resource == Photo::"p");
"#;
    let engine = PolicyEngine::new_from_str(policy).unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None)),
        action: Action::new("read", None),
        resource: Resource::new("Photo", "p"),
    };

    let first = engine.list_policies(&request).unwrap();
    let second = engine.list_policies(&request).unwrap();

    let first_ids = first
        .matches()
        .iter()
        .map(|m| m.cedar_id.clone())
        .collect::<Vec<_>>();
    let second_ids = second
        .matches()
        .iter()
        .map(|m| m.cedar_id.clone())
        .collect::<Vec<_>>();

    let mut sorted = first_ids.clone();
    sorted.sort();
    assert_eq!(first_ids, second_ids);
    assert_eq!(first_ids, sorted);
}

#[test]
fn test_list_policies_for_user_with_groups_and_namespace() {
    // Test that the API supports groups and namespaces
    let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();

    let user_policies = engine
        .list_policies_for_user("alice", &["dbusers"], &["Database"])
        .expect("Failed to list permissions");

    // Should match both the direct user constraint and the group constraint
    assert_eq!(user_policies.policies().len(), 2);
}
