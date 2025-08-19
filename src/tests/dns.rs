#[cfg(test)]
mod tests {
    use std::{collections::HashMap, vec};

    use yare::parameterized;

    use crate::{
        Action, Decision, Principal, Request, Resource, User, engine::PolicyEngine,
        models::AttrValue,
    };

    const DNS_POLICY: &str = include_str!("../../testdata/dns.cedar");
    const NAMESPACE: &str = "DNS";

    fn init_engine() -> PolicyEngine {
        PolicyEngine::new_from_str(DNS_POLICY).unwrap()
    }

    fn namespaces() -> Vec<String> {
        vec![NAMESPACE.to_string()]
    }

    fn users() -> HashMap<String, User> {
        let mut users_map: HashMap<String, User> = HashMap::new();

        let default_ns = Some(namespaces());
        let admins_only = Some(vec!["admins".to_string()]);
        let users_only = Some(vec!["users".to_string()]);
        let all_groups = Some(vec!["admins".to_string(), "users".to_string()]);

        users_map.insert(
            "alice".to_string(),
            User::new("alice", all_groups.clone(), default_ns.clone()),
        );

        users_map.insert(
            "bob".to_string(),
            User::new("bob", users_only.clone(), default_ns.clone()),
        );

        users_map.insert(
            "charlie".to_string(),
            User::new("charlie", admins_only.clone(), default_ns.clone()),
        );

        users_map.insert("super".to_string(), User::new("super", None, None));

        users_map
    }

    fn get_user(name: &str) -> User {
        users().get(name).cloned().unwrap()
    }

    fn get_action(action: &str) -> Action {
        Action::new(action, Some(vec![NAMESPACE.to_string()]))
    }

    #[test]
    fn test_dns_policy_has_correct_policy_count() {
        let engine = init_engine();
        let policies = engine.policies().unwrap();
        assert_eq!(policies.len(), 9);
    }

    #[parameterized(
        alice_create_host_allow = { "alice", "create_host" },
        alice_delete_host_allow = { "alice", "delete_host" },
        bob_create_host_deny = { "bob", "create_host" },
        bob_delete_host_deny = { "bob", "delete_host" },
        bob_view_host_allow = { "bob", "view_host" },   
        charlie_create_host_allow = { "charlie", "create_host" },
        charlie_delete_host_explicit_deny = { "charlie", "delete_host" },
        charlie_view_host_allow = { "charlie", "view_host" },
        super_create_host_allow = { "super", "create_host" },
        super_delete_host_allow = { "super", "delete_host" }
    )]
    fn test_host_operations(user: &str, action: &str) {
        let engine = init_engine();
        let user = get_user(user);
        let action = get_action(action);

        let request = Request {
            principal: Principal::User(user),
            action: action.into(),
            resource: Resource::new("Host", "hostname.example.com")
                .with_attr("name", AttrValue::String("hostname.example.com".into()))
                .with_attr("ip", AttrValue::Ip("192.0.2.1".into())),
        };

        let decision = engine.evaluate(&request).unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(decision);
        });
    }

    // As Alice has the `view_host` permission from both the `admins` and `users` groups,
    // we can get either of the two policies in return. This simply tests that she doesn't
    // get denied.
    #[test]
    fn test_dual_match() {
        let engine = init_engine();
        let user = get_user("alice");
        let action = get_action("view_host");
        let request = Request {
            principal: Principal::User(user),
            action: action.into(),
            resource: Resource::new("Host", "hostname.example.com")
                .with_attr("name", AttrValue::String("hostname.example.com".into()))
                .with_attr("ip", AttrValue::Ip("192.0.2.1".into())),
        };
        let decision = engine.evaluate(&request).unwrap();
        assert_ne!(decision, Decision::Deny);
    }
}
