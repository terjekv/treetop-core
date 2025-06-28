use cedar_policy::{
    Authorizer, Entities, Entity, EntityUid, Policy, PolicySet, PrincipalConstraint,
    Request as CedarRequest,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::models::{PermitPolicy, UserPolicies};
use crate::traits::CedarAtom;
use crate::{
    error::PolicyError,
    loader,
    models::{Decision, FromDecisionWithPolicy, Request},
};

use tracing::{debug, info, warn};
/// The main engine handle. Cloneable and thread-safe.
#[derive(Clone)]
pub struct PolicyEngine {
    inner: Arc<RwLock<PolicySet>>,
}

impl PolicyEngine {
    pub fn new_from_str(policy_text: &str) -> Result<Self, PolicyError> {
        let set = loader::compile_policy(policy_text)?;
        Ok(PolicyEngine {
            inner: Arc::new(RwLock::new(set)),
        })
    }

    pub fn reload_from_str(&self, policy_text: &str) -> Result<(), PolicyError> {
        let new_set = loader::compile_policy(policy_text)?;
        *self.inner.write().unwrap() = new_set;
        Ok(())
    }

    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        let schema: Option<&cedar_policy::Schema> = None;

        debug!(
            event = "Request",
            phase = "Evaluation",
            principal = request.principal.to_string(),
            action = request.action.to_string(),
            resource = request.resource.to_string(),
            groups = request.groups.to_string()
        );

        // 1. Turn your Atom types into EntityUids (the “P, A, R” in PARC)
        let principal: EntityUid = request.principal.cedar_entity_uid()?;
        let action: EntityUid = request.action.cedar_entity_uid()?;
        let resource: EntityUid = request.resource.cedar_entity_uid()?;

        // 2. Build an Context from the resource, this may be empty.
        let context = request.resource.cedar_ctx()?;

        debug!(
            event = "Request",
            phase = "Parsed",
            principal = principal.to_string(),
            action = action.to_string(),
            resource = resource.to_string(),
            context = context.to_string()
        );

        // 3. Create the Cedar request
        let cedar_req = CedarRequest::new(principal.clone(), action, resource, context, None)?;

        // 4. Create Entities for the request
        // 4a. Create EntityUids for each group
        let mut group_uids = HashSet::new();
        for group in &request.groups.0 {
            let g = group.cedar_entity_uid()?;
            group_uids.insert(g);
        }

        // 4b. Create an Entity for the principal, with the EntityUid of those groups as parents
        let principal_entity = Entity::new(principal.clone(), HashMap::new(), group_uids.clone())?;

        // 4c. Create Entities for each group out of the EntityUids we created in 4a
        let group_entities: Vec<Entity> = group_uids.into_iter().map(Entity::with_uid).collect();

        // 5. Create the complete Entities collection, including the resource, principal, and groups
        let entities = Entities::empty()
            .add_entities(
                vec![request.resource.cedar_entity()?, principal_entity],
                schema,
            )?
            .add_entities(group_entities, schema)?;

        debug!(
            event = "Request",
            phase = "Entities",
            entities = request.resource.cedar_entity()?.to_string()
        );

        // 6. Run the authorizer
        let guard = self.inner.read()?;
        let result = Authorizer::new().is_authorized(&cedar_req, &guard, &entities);

        debug!(event = "Request", phase = "Result", result = ?result.decision());
        let mut permit_policy = PermitPolicy::default();

        if result.decision() == cedar_policy::Decision::Allow {
            let reasons = result.diagnostics().reason();
            for reason in reasons {
                let policy = guard.policy(reason);
                if let Some(policy) = policy {
                    permit_policy.literal = policy.to_string().clone();
                    permit_policy.json = policy.to_json().unwrap_or_default();
                    info!(
                        event = "Request",
                        phase = "Policy",
                        reason = reason.to_string(),
                        policy = permit_policy.literal
                    );
                } else {
                    warn!(
                        event = "Request",
                        phase = "Policy",
                        reason = reason.to_string()
                    );
                }
            }
        }

        Ok(Decision::from_decision_with_policy(
            result.decision(),
            permit_policy,
        ))
    }

    pub fn list_policies_for_user(
        &self,
        user: &str,
        scope: Vec<String>,
    ) -> Result<UserPolicies, PolicyError> {
        let guard = self.inner.read()?;
        let policies = guard.policies();

        // Join the user and then scope into a ::-separated string
        let user_with_scope = if scope.is_empty() {
            format!("User::\"{user}\"")
        } else {
            format!("User::\"{}\"::{}", scope.join("::"), user)
        };

        let uid: EntityUid = user_with_scope.parse()?;

        let mut matching_policies: Vec<Policy> = Vec::new();

        for policy in policies {
            // Check if the policy applies to the user
            let pc = policy.principal_constraint();
            if pc == PrincipalConstraint::Eq(uid.clone()) || pc == PrincipalConstraint::Any {
                matching_policies.push(policy.clone());
            }
        }

        Ok(UserPolicies::new(user, &matching_policies))
    }

    pub fn policies(&self) -> Result<Vec<Policy>, PolicyError> {
        let guard = self.inner.read()?;
        Ok(guard.policies().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Group;
    use crate::host_patterns::initialize_host_patterns;
    use crate::models::Groups;
    use crate::models::{
        Decision::Allow, Decision::Deny, Resource, Resource::Host, Resource::Photo,
    };
    use insta::assert_json_snapshot;
    use yare::parameterized;

    const TEST_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITHOUT_BOB: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITH_CONTEXT: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.name like "web*" &&
    resource.ip.isInRange(ip("192.0.1.0/24"))
};

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
) when {
    resource.name like "bob*" &&
    resource.ip.isInRange(ip("192.0.0.0/24"))
};
"#;

    const TEST_PERMISSION_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITH_FORBID: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);
forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);
forbid (
    principal,
    action == Action::"delete",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITH_HOST_PATTERNS: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.nameLabels.contains("example_domain")
};

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
) when {
    resource.nameLabels.contains("valid_web_name") &&
    resource.nameLabels.contains("example_domain")
};
"#;

    const TEST_POLICY_ACTION_ONLY_HERE: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"only_here",
    resource
);
"#;

    const TEST_POLICY_GENERIC_RESOURCE: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"assign_gateway",
    resource is Gateway
) when {
    resource.id == "mygateway"
};
"#;

    const TEST_POLICY_WITH_GROUPS: &str = r#"
permit (
    principal in Group::"admins",
    action in [Action::"delete", Action::"view"],
    resource is Photo
);

permit (
    principal in Group::"users",
    action == Action::"view",
    resource is Photo
);
"#;

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
        let resource = Resource::Photo {
            id: resource.to_string(),
        };

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: Groups(vec![]),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
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
            principal: user.into(),
            action: action.into(),
            groups: Groups(vec![]),
            resource: Host {
                name: host_name.into(),
                ip: ip.parse().unwrap(),
            },
        };
        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
    }

    #[test]
    fn test_reload_policy() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
        let request = Request {
            principal: "bob".into(),
            action: "view".into(),
            groups: Groups(vec![]),
            resource: Photo {
                id: "VacationPhoto94.jpg".into(),
            },
        };

        assert!(matches!(engine.evaluate(&request).unwrap(), Allow { .. }));

        engine.reload_from_str(TEST_POLICY_WITHOUT_BOB).unwrap();
        assert_eq!(engine.evaluate(&request).unwrap(), Deny);
    }

    #[parameterized(
        alice_permissions = { "alice", vec![], 2, vec!["create_host", "delete", "edit", "view"] },
        bob_permissions = { "bob", vec![], 1, vec!["view"] },
        charlie_permissions = { "charlie", vec![], 0, vec![] },
    )]
    fn test_list_permissions(
        user: &str,
        scope: Vec<String>,
        expected_policies: usize,
        expected_actions: Vec<&str>,
    ) {
        let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();
        let user_policies = engine
            .list_policies_for_user(user, scope)
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
        let perms = engine.list_policies_for_user("alice", vec![]).unwrap();

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
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg" },
        alice_edit_deny_explicit = { "alice", "edit", "VacationPhoto94.jpg" },
        alice_delete_forbid_any = { "alice", "delete", "VacationPhoto94.jpg" },
    )]
    fn test_policy_with_forbid(user: &str, action: &str, resource: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::Photo {
            id: resource.to_string(),
        };

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: Groups(vec![]),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();

        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
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
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_HOST_PATTERNS).unwrap();
        initialize_host_patterns(vec![
            (
                "valid_web_name".to_string(),
                regex::Regex::new(r"^web.*").unwrap(),
            ),
            (
                "example_domain".to_string(),
                regex::Regex::new(r"example\.com$").unwrap(),
            ),
        ]);

        let request = Request {
            principal: username.into(),
            action: "create_host".into(),
            groups: Groups(vec![]),
            resource: Host {
                name: host_name.to_string(),
                ip: "10.0.0.1".parse().unwrap(),
            },
        };
        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
    }

    #[parameterized(
        alice_allow = {"alice" },
        bob_deny = {"bob" }
    )]
    fn test_only_here_policy(username: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_ACTION_ONLY_HERE).unwrap();
        let request = Request {
            principal: username.into(),
            action: "only_here".into(),
            groups: Groups(vec![]),
            resource: Host {
                name: "irrelevant.example.com".into(),
                ip: "10.0.0.1".parse().unwrap(),
            },
        };

        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
    }

    #[parameterized(
        alice_assign_gateway_allow = { "alice", "assign_gateway", "mygateway" },
        bob_assign_gateway_deny = { "bob", "assign_gateway", "mygateway" },
        alice_assign_gateway_wrong_id_deny = { "alice", "assign_gateway", "wronggateway" },
    )]
    fn test_generic_policies(user: &str, action: &str, resource_id: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_GENERIC_RESOURCE).unwrap();
        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: Groups(vec![]),
            resource: Resource::Generic {
                kind: "Gateway".to_string(),
                id: resource_id.to_string(),
            },
        };
        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
    }

    #[parameterized(
        alice_delete_allow = { "alice", &["admins"], "delete" },
        alice_view_allow = { "alice", &["admins"], "view" },
        bob_delete_deny = { "bob", &["users"], "delete" },
        bob_view_allow = { "bob", &["users"], "view" },
    )]
    fn test_policy_with_groups(user: &str, groups: &[&str], action: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::Photo {
            id: "photo.jpg".to_string(),
        };

        let groups: Vec<Group> = groups.iter().map(|g| Group(g.to_string())).collect();

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: Groups(groups),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(decision);
        });
    }
}
