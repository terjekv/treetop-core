use cedar_policy::{
    Authorizer, Entities, Entity, EntityUid, Policy, PolicySet, PrincipalConstraint,
    Request as CedarRequest,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;
use std::vec;

use crate::labels::LABEL_REGISTRY;
use crate::models::{Decision, PermitPolicy, PolicyVersion, UserPolicies};
use crate::traits::CedarAtom;
use crate::{Groups, Principal};
use crate::{error::PolicyError, loader, models::FromDecisionWithPolicy, models::Request};
use arc_swap::ArcSwap;

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Immutable snapshot of a compiled policy set, along with metadata.
#[derive(Debug)]
struct PolicySnapshot {
    set: PolicySet,
    version: PolicyVersion,
}

/// Convenience alias for a shared policy snapshot.
type Snapshot = Arc<PolicySnapshot>;

impl PolicySnapshot {
    fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        let set = loader::compile_policy(policy_text)?;

        let mut hasher = Sha256::new();
        hasher.update(policy_text.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Ok(PolicySnapshot {
            set,
            version: PolicyVersion {
                hash,
                loaded_at: humantime::format_rfc3339(SystemTime::now()).to_string(),
            },
        })
    }

    fn policy_set(&self) -> &PolicySet {
        &self.set
    }

    fn version(&self) -> PolicyVersion {
        self.version.clone()
    }
}
/// The main engine handle. Cloneable and thread-safe.
#[derive(Clone)]
pub struct PolicyEngine {
    /// Shared pointer to an `ArcSwap` holding the current `Snapshot`.
    inner: Arc<ArcSwap<Snapshot>>,
}

impl From<PolicyEngine> for PolicyVersion {
    fn from(engine: PolicyEngine) -> Self {
        engine.current_version()
    }
}

impl PolicyEngine {
    pub fn new_from_str(policy_text: &str) -> Result<Self, PolicyError> {
        let snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text(policy_text)?);
        Ok(PolicyEngine {
            inner: Arc::new(ArcSwap::from(Arc::new(snapshot))),
        })
    }

    pub fn reload_from_str(&self, policy_text: &str) -> Result<(), PolicyError> {
        let new_snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text(policy_text)?);
        self.inner.store(Arc::new(new_snapshot));
        Ok(())
    }

    /// Get the current snapshot using a short-lived read lock, then drop the lock.
    fn current_snapshot(&self) -> Snapshot {
        // `load_full` returns `Arc<Arc<PolicySnapshot>>`; deref one level.
        let outer = self.inner.load_full();
        Arc::clone(&outer)
    }

    /// Get the current policy version.
    pub fn current_version(&self) -> PolicyVersion {
        self.current_snapshot().version()
    }

    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        let schema: Option<&cedar_policy::Schema> = None;

        let groups = match &request.principal {
            Principal::User(user) => user.groups().clone(),
            Principal::Group(_) => Groups::default(),
        };

        let now = std::time::Instant::now();
        let snapshot = self.current_snapshot();
        let version = snapshot.version();

        debug!(
            event = "Request",
            phase = "Evaluation",
            principal = request.principal.to_string(),
            action = request.action.to_string(),
            resource = request.resource.to_string(),
            groups = groups.to_string()
        );

        // resource is &request.resource; take a working copy so we can mutate attrs with labels
        let mut resource_dyn = request.resource.clone();
        LABEL_REGISTRY.apply(&mut resource_dyn);

        // Build resource entity from the (now augmented) attrs

        // 1. Turn your Atom types into EntityUids (the “P, A, R” in PARC)
        let principal: EntityUid = request.principal.cedar_entity_uid()?;
        let action: EntityUid = request.action.cedar_entity_uid()?;
        let resource: EntityUid = resource_dyn.cedar_entity_uid()?;
        let resource_attrs = resource_dyn.cedar_attr()?;

        // 2. Build an Context from the resource, this may be empty.
        let context = request.resource.cedar_ctx()?;

        debug!(
            event = "Request",
            phase = "Parsed",
            principal = principal.to_string(),
            action = action.to_string(),
            resource = resource.to_string(),
            context = context.to_string(),
            groups = groups.to_string(),
            attrs = ?resource_attrs
        );

        let resource_entity =
            cedar_policy::Entity::new(resource.clone(), resource_attrs, Default::default())?;

        // 3. Create the Cedar request
        let cedar_req = CedarRequest::new(principal.clone(), action, resource, context, None)?;

        // 4. Create Entities for the request
        // 4a. Create EntityUids for each group
        let mut group_uids = HashSet::new();
        for group in groups.clone() {
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
                vec![
                    resource_dyn.cedar_entity()?,
                    principal_entity,
                    resource_entity,
                ],
                schema,
            )?
            .add_entities(group_entities, schema)?;

        debug!(
            event = "Request",
            phase = "Entities",
            entities = entities
                .iter()
                .map(|e| format!("[{e}]"))
                .collect::<Vec<_>>()
                .join(", ")
                .replace('\n', "")
        );

        // 6. Run the authorizer against the current immutable snapshot
        let result = Authorizer::new().is_authorized(&cedar_req, &snapshot.set, &entities);

        debug!(
            event = "Request",
            phase = "Result",
            time = now.elapsed().as_micros(),
            result = ?result.decision(),
            policy_hash = %version.hash,
            policy_loaded_at = %version.loaded_at,
        );
        let mut permit_policy = PermitPolicy::default();

        if result.decision() == cedar_policy::Decision::Allow {
            let reasons = result.diagnostics().reason();
            for reason in reasons {
                let policy = snapshot.set.policy(reason);
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
            version,
        ))
    }

    pub fn list_policies_for_user(
        &self,
        user: &str,
        namespace: Vec<String>,
    ) -> Result<UserPolicies, PolicyError> {
        let snapshot = self.current_snapshot();
        let policies = snapshot.set.policies();

        // Join the user and then namespace into a ::-separated string
        let user_with_namespace = if namespace.is_empty() {
            format!("User::\"{user}\"")
        } else {
            format!("User::\"{}\"::{}", namespace.join("::"), user)
        };

        let uid: EntityUid = user_with_namespace.parse()?;

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
        let snapshot = self.current_snapshot();
        Ok(snapshot.policy_set().policies().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::labels::{LABEL_REGISTRY, RegexLabeler};
    use crate::models::AttrValue;
    use crate::models::{Decision::Allow, Decision::Deny, Group, Resource};
    use crate::snapshot_decision;
    use crate::{Action, User};
    use regex::Regex;
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

    const TEST_POLICY_BY_ID: &str = r#"
@id("id_of_policy")
permit (
    principal == User::"alice",
    action, 
    resource
);
"#;

    const TEST_POLICY_WITH_NAMESPACES: &str = r#"
permit (
    principal == Database::User::"alice",
    action in [Database::Action::"create_table", Database::Action::"view_table"],
    resource is Database::Table
);

permit (
    principal in Database::Group::"dbusers",
    action == Database::Action::"view_table",
    resource is Database::Table
);

permit (
    principal in Furniture::Group::"carpenters",
    action == Furniture::Action::"create_table",
    resource is Furniture::Table
);
"#;

    const TEST_POLICY_WITH_IP: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.ip.isInRange(ip("192.168.0.0/24"))
};
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
        let resource = Resource::new("Photo", resource.to_string())
            .with_attr("name", AttrValue::String(resource.to_string()));

        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: action.into(),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
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
            action: action.into(),
            resource: Resource::new("Host", host_name)
                .with_attr("name", AttrValue::String(host_name.into()))
                .with_attr("ip", AttrValue::Ip(ip.into())),
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[test]
    fn test_reload_policy() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
        let request = Request {
            principal: Principal::User(User::new("bob", None, None)),
            action: "view".into(),
            resource: Resource::from_str("Photo::VacationPhoto94.jpg").unwrap(),
        };

        assert!(matches!(engine.evaluate(&request).unwrap(), Allow { .. }));

        engine.reload_from_str(TEST_POLICY_WITHOUT_BOB).unwrap();
        assert!(matches!(engine.evaluate(&request).unwrap(), Deny { .. }));
    }

    #[parameterized(
        alice_permissions = { "alice", vec![], 2, vec!["create_host", "delete", "edit", "view"] },
        bob_permissions = { "bob", vec![], 1, vec!["view"] },
        charlie_permissions = { "charlie", vec![], 0, vec![] },
    )]
    fn test_list_permissions(
        user: &str,
        namespaces: Vec<String>,
        expected_policies: usize,
        expected_actions: Vec<&str>,
    ) {
        let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();
        let user_policies = engine
            .list_policies_for_user(user, namespaces)
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
        let resource = Resource::new("Photo", resource.to_string())
            .with_attr("name", AttrValue::String(resource.to_string()));

        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: action.into(),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
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
        let patterns = vec![
            ("valid_web_name".to_string(), Regex::new(r"^web.*").unwrap()),
            (
                "example_domain".to_string(),
                Regex::new(r"example\.com$").unwrap(),
            ),
        ];
        let labeler =
            RegexLabeler::new("Host", "name", "nameLabels", patterns.into_iter().collect());

        LABEL_REGISTRY.load(vec![Arc::new(labeler)]);

        let request = Request {
            principal: Principal::User(User::new(username, None, None)),
            action: "create_host".into(),
            resource: Resource::new("Host", host_name.to_string())
                .with_attr("name", AttrValue::String(host_name.into()))
                .with_attr("ip", AttrValue::Ip("10.0.0.1".into())),
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_allow = {"alice" },
        bob_deny = {"bob" }
    )]
    fn test_only_here_policy(username: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_ACTION_ONLY_HERE).unwrap();
        let request = Request {
            principal: Principal::User(User::new(username, None, None)),
            action: "only_here".into(),
            resource: Resource::new("Photo", "irrelevant_photo.jpg")
                .with_attr("name", AttrValue::String("irrelevant.example.com".into()))
                .with_attr("ip", AttrValue::Ip("10.0.0.1".into())),
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
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
            action: action.into(),
            resource: Resource::new("Gateway", resource_id.to_string()),
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
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
            action: action.into(),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
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
            action: action.into(),
            resource,
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[test]
    fn test_policy_by_id() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_BY_ID).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", Some(vec!["admins".to_string()]), None)),
            action: "view".into(),
            resource: Resource::new("Photo", "VacationPhoto94.jpg".to_string()),
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
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
        snapshot_decision!(decision);
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
        snapshot_decision!(decision);
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
}
