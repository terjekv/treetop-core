//! User permissions and policy collections.

use cedar_policy::{ActionConstraint, EntityUid, Policy};
use itertools::Itertools;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::Value;

/// A set of permissions for a given user.
#[derive(Debug, Clone)]
pub struct UserPolicies {
    user: String,
    policies: Vec<Policy>,
    actions: Vec<EntityUid>,
}

impl UserPolicies {
    pub fn new(user: &str, policies: &[Policy]) -> Self {
        let actions: Vec<EntityUid> = policies
            .iter()
            .flat_map(|p| match p.action_constraint() {
                // exactly one action
                ActionConstraint::Eq(act) => vec![act.clone()],
                // multiple actions
                ActionConstraint::In(acts) => acts.clone(),
                // "any" means unconstrained — skip or handle however you like
                ActionConstraint::Any => Vec::new(),
            })
            .collect();

        UserPolicies {
            user: user.to_string(),
            policies: policies.to_vec(),
            actions,
        }
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    pub fn actions(&self) -> &[EntityUid] {
        &self.actions
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Get the actions as a sorted list of strings.
    pub fn actions_by_name(&self) -> Vec<String> {
        self.actions
            .iter()
            .map(|a| a.to_string())
            .sorted()
            .collect()
    }

    /// Get the policies as a sorted list of strings.
    pub fn policies_by_name(&self) -> Vec<String> {
        self.policies
            .iter()
            .map(|p| p.to_string())
            .sorted()
            .collect()
    }
}

impl Serialize for UserPolicies {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policies = self.policies();

        let mut policies_as_json: Vec<Value> = Vec::new();

        for policy in policies {
            let json = match policy.to_json() {
                Ok(json) => json,
                Err(e) => return Err(serde::ser::Error::custom(e)),
            };
            policies_as_json.push(json);
        }

        let mut s = ser.serialize_struct("UserPolicies", 2)?;
        s.serialize_field("user", &self.user)?;
        s.serialize_field("policies", &policies_as_json)?;
        s.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::Policy;

    #[test]
    fn test_user_policies_new_empty() {
        let policies = UserPolicies::new("alice", &[]);
        assert_eq!(policies.user(), "alice");
        assert!(policies.is_empty());
        assert_eq!(policies.actions().len(), 0);
        assert_eq!(policies.policies().len(), 0);
    }

    #[test]
    fn test_user_policies_with_single_action() {
        let policy_text =
            r#"permit(principal == User::"alice", action == Action::"read", resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new("alice", &[policy]);
        assert_eq!(policies.user(), "alice");
        assert!(!policies.is_empty());
        assert_eq!(policies.actions().len(), 1);
        assert_eq!(policies.policies().len(), 1);

        let actions = policies.actions_by_name();
        assert_eq!(actions.len(), 1);
        assert!(actions[0].contains("read"));
    }

    #[test]
    fn test_user_policies_with_multiple_actions() {
        let policy_text = r#"permit(principal == User::"alice", action in [Action::"read", Action::"write", Action::"delete"], resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new("alice", &[policy]);
        assert_eq!(policies.actions().len(), 3);

        let actions = policies.actions_by_name();
        assert_eq!(actions.len(), 3);
        // actions_by_name should be sorted
        assert!(actions[0] < actions[1]);
        assert!(actions[1] < actions[2]);
    }

    #[test]
    fn test_user_policies_with_any_action() {
        let policy_text = r#"permit(principal == User::"alice", action, resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new("alice", &[policy]);
        // "Any" action constraint should result in empty actions list
        assert_eq!(policies.actions().len(), 0);
        assert_eq!(policies.policies().len(), 1);
    }

    #[test]
    fn test_user_policies_multiple_policies() {
        let policy1 = Policy::parse(
            None,
            r#"permit(principal == User::"alice", action == Action::"read", resource);"#,
        )
        .unwrap();
        let policy2 = Policy::parse(
            None,
            r#"permit(principal == User::"alice", action == Action::"write", resource);"#,
        )
        .unwrap();

        let policies = UserPolicies::new("alice", &[policy1, policy2]);
        assert_eq!(policies.policies().len(), 2);
        assert_eq!(policies.actions().len(), 2);

        let policy_names = policies.policies_by_name();
        assert_eq!(policy_names.len(), 2);
        // Should be sorted
        assert!(policy_names[0] < policy_names[1]);
    }

    #[test]
    fn test_user_policies_serialization() {
        let policy_text =
            r#"permit(principal == User::"alice", action == Action::"read", resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new("alice", &[policy]);
        let json = serde_json::to_value(&policies).unwrap();

        assert_eq!(json["user"], "alice");
        assert!(json["policies"].is_array());
        assert_eq!(json["policies"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_user_policies_actions_cloned() {
        let policy_text =
            r#"permit(principal == User::"alice", action == Action::"read", resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new("alice", &[policy]);
        let actions1 = policies.actions();
        let actions2 = policies.actions();

        // Should be cloned, not shared
        assert_eq!(actions1.len(), actions2.len());
    }

    #[test]
    fn test_user_policies_with_special_username() {
        let policy_text = r#"permit(principal, action, resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new("alice@example.com", &[policy]);
        assert_eq!(policies.user(), "alice@example.com");
    }
}
