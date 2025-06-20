use cedar_policy::{
    Authorizer, Entities, EntityUid, Policy, PolicySet, PrincipalConstraint,
    Request as CedarRequest,
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
        println!("Evaluating request: {:?}", request);
        // 1. Turn your Atom types into EntityUids (the “P, A, R” in PARC)
        let principal: EntityUid = request.principal.cedar_entity_uid()?;
        let action: EntityUid = request.action.cedar_entity_uid()?;
        let resource: EntityUid = request.resource.cedar_entity_uid()?;

        // 2. Build an Context from the resource, this may be empty.
        let context = request.resource.cedar_ctx()?;

        println!("Principal: {:?}", principal);
        println!("Action: {:?}", action);
        println!("Resource: {:?}", resource);
        println!("Context: {:?}", context);

        // 3. Create the Cedar request
        let cedar_req = CedarRequest::new(principal, action, resource, context, None)?;

        // 4. For now, no group‐membership facts or other entities
        let entities = Entities::empty();
        let entities = entities.add_entities(vec![request.resource.cedar_entity()?], None)?;

        println!("Entities: {:?}", entities);

        // 5. Run the authorizer
        let guard = self.inner.read()?;
        let result = Authorizer::new().is_authorized(&cedar_req, &guard, &entities);

        println!("Result: {:?}", result);

        if result.decision() == cedar_policy::Decision::Allow {
            let reasons = result.diagnostics().reason();
            for reason in reasons {
                let policy = guard.policy(reason);
                if let Some(policy) = policy {
                    println!("Policy {}: {}", reason, policy);
                } else {
                    println!("No policy found for reason: {}", reason);
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
            format!("User::\"{}\"", user)
        } else {
            format!("User::\"{}\"::{}", scope.join("::"), user)
        };

        let uid: EntityUid = user_with_scope.parse()?;

        let mut matching_policies: Vec<Policy> = Vec::new();
        for policy in policies {
            // Check if the policy applies to the user
            if policy.principal_constraint() != PrincipalConstraint::Eq(uid.clone()) {
                continue;
            }
            // Check if the policy is a permit policy
            if policy.effect() != cedar_policy::Effect::Permit {
                continue;
            }
            matching_policies.push(policy.clone());
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
    #[parameterized(
        alice_edit_allow = { "alice", "edit", Photo { id: "VacationPhoto94.jpg".into() }, Allow },
        alice_view_allow = { "alice", "view", Photo { id: "VacationPhoto94.jpg".into() }, Allow },
        alice_delete_allow = { "alice", "delete", Photo { id: "VacationPhoto94.jpg".into() }, Allow },
        bob_view_allow = { "bob", "view", Photo { id: "VacationPhoto94.jpg".into() }, Allow },
        bob_edit_deny = { "bob", "edit", Photo { id: "VacationPhoto94.jpg".into() }, Deny },
        charlie_view_deny = { "charlie", "view", Photo { id: "VacationPhoto94.jpg".into() }, Deny },
    )]
    fn test_evaluate_requests(user: &str, action: &str, resource: Resource, expected: Decision) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();

        let request = Request {
            principal: user.into(),
            action: action.into(),
            groups: vec![],
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        assert_eq!(decision, expected);
    }

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

    const TEST_POLICY_WITHOUT_BOB: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
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
}
