use cedar_policy::{
    Authorizer, Effect::Forbid as CedarForbid, Effect::Permit as CedarPermit, Entities, EntityUid,
    Policy, PolicySet, PrincipalConstraint, Request as CedarRequest,
};
use std::sync::{Arc, RwLock};

use crate::models::UserPolicies;
use crate::traits::CedarAtom;
use crate::{
    error::PolicyError,
    loader,
    models::{Decision, Request},
};

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
        println!("Evaluating request: {request:?}");
        // 1. Turn your Atom types into EntityUids (the “P, A, R” in PARC)
        let principal: EntityUid = request.principal.cedar_entity_uid()?;
        let action: EntityUid = request.action.cedar_entity_uid()?;
        let resource: EntityUid = request.resource.cedar_entity_uid()?;

        // 2. Build an Context from the resource, this may be empty.
        let context = request.resource.cedar_ctx()?;

        println!("Principal: {principal:?}");
        println!("Action: {action:?}");
        println!("Resource: {resource:?}");
        println!("Context: {context:?}");

        // 3. Create the Cedar request
        let cedar_req = CedarRequest::new(principal, action, resource, context, None)?;

        // 4. For now, no group‐membership facts or other entities
        let entities = Entities::empty();
        let entities = entities.add_entities(vec![request.resource.cedar_entity()?], None)?;

        println!("Entities: {entities:?}");

        // 5. Run the authorizer
        let guard = self.inner.read()?;
        let result = Authorizer::new().is_authorized(&cedar_req, &guard, &entities);

        println!("Result: {result:?}");

        if result.decision() == cedar_policy::Decision::Allow {
            let reasons = result.diagnostics().reason();
            for reason in reasons {
                let policy = guard.policy(reason);
                if let Some(policy) = policy {
                    println!("Policy {reason}: {policy}");
                } else {
                    println!("No policy found for reason: {reason}");
                }
            }
        }

        Ok(result.decision().into())
    }

    pub fn list_permissions_for_user(
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
                if policy.effect() == CedarPermit {
                    matching_policies.push(policy.clone());
                } else if policy.effect() == CedarForbid {
                    matching_policies.push(policy.clone());
                }
            }
        }

        Ok(UserPolicies::new(user, &matching_policies))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Decision::Allow, Decision::Deny, Resource, Resource::Host, Resource::Photo,
    };
    use serde_json::Value;
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

    #[parameterized(
        alice_edit_allow = { "alice", "edit", "VacationPhoto94.jpg", Allow },
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg", Allow },
        alice_delete_allow = { "alice", "delete", "VacationPhoto94.jpg", Allow },
        alice_view_deny_wrong_photo = { "alice", "view", "wrongphoto.jpg", Deny },
        bob_view_allow = { "bob", "view", "VacationPhoto94.jpg", Allow },
        bob_edit_deny = { "bob", "edit", "VacationPhoto94.jpg", Deny },
        bob_view_deny_wrong_photo = { "bob", "edit", "wrongphoto.jpg", Deny },
        charlie_view_deny = { "charlie", "view", "VacationPhoto94.jpg", Deny },
    )]
    fn test_evaluate_requests(user: &str, action: &str, resource: &str, expected: Decision) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::Photo {
            id: resource.to_string(),
        };

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: vec![],
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        assert_eq!(decision, expected);
    }

    #[parameterized(
        alice_create_host_allow = { "alice", "create_host", "web-01.example.com", "192.0.1.1", Allow },
        bob_create_host_allow = { "bob", "create_host", "bob-01.example.com", "192.0.0.1", Allow },
        alice_create_host_wrong_net_deny = { "alice", "create_host", "web-99.example.com", "192.0.2.1", Deny },
        alice_create_host_wrong_name_deny = { "alice", "create_host", "abc.example.com", "192.0.1.2", Deny },
    )]
    fn test_create_host_requests(
        user: &str,
        action: &str,
        host_name: &str,
        ip: &str,
        expected: Decision,
    ) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_CONTEXT).unwrap();

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: vec![],
            resource: Host {
                name: host_name.into(),
                ip: ip.parse().unwrap(),
            },
        };
        let decision = engine.evaluate(&request).unwrap();
        assert_eq!(decision, expected);
    }

    #[test]
    fn test_reload_policy() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
        let request = Request {
            principal: "bob".into(),
            action: "view".into(),
            groups: vec![],
            resource: Photo {
                id: "VacationPhoto94.jpg".into(),
            },
        };
        assert_eq!(engine.evaluate(&request).unwrap(), Allow);

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
            .list_permissions_for_user(user, scope)
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

    #[test]
    fn test_serialize_user_permissions() {
        let combined = TEST_PERMISSION_POLICY.to_string() + TEST_POLICY_WITH_CONTEXT;
        let engine = PolicyEngine::new_from_str(&combined).unwrap();
        let perms = engine.list_permissions_for_user("alice", vec![]).unwrap();

        let expected_serialized = r#"{"user":"alice","policies":[{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"in","entities":[{"type":"Action","id":"view"},{"type":"Action","id":"edit"},{"type":"Action","id":"delete"}]},"resource":{"op":"==","entity":{"type":"Photo","id":"VacationPhoto94.jpg"}},"conditions":[]},{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"==","entity":{"type":"Action","id":"create_host"}},"resource":{"op":"is","entity_type":"Host"},"conditions":[]},{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"==","entity":{"type":"Action","id":"create_host"}},"resource":{"op":"is","entity_type":"Host"},"conditions":[{"kind":"when","body":{"&&":{"left":{"like":{"left":{".":{"left":{"Var":"resource"},"attr":"name"}},"pattern":[{"Literal":"w"},{"Literal":"e"},{"Literal":"b"},"Wildcard"]}},"right":{"isInRange":[{".":{"left":{"Var":"resource"},"attr":"ip"}},{"ip":[{"Value":"192.0.1.0/24"}]}]}}}}]}]}"#;

        let actual: Value = serde_json::to_value(&perms).unwrap();
        let expected: Value = serde_json::from_str(expected_serialized).unwrap();

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
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg", Allow },
        alice_edit_deny_explicit = { "alice", "edit", "VacationPhoto94.jpg", Deny },
        alice_delete_forbid_any = { "alice", "delete", "VacationPhoto94.jpg", Deny },
    )]
    fn test_policy_with_forbid(user: &str, action: &str, resource: &str, expected: Decision) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::Photo {
            id: resource.to_string(),
        };

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: vec![],
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        assert_eq!(decision, expected);
    }
}
