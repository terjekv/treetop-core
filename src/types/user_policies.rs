//! User permissions and policy collections.

use cedar_policy::{ActionConstraint, EntityUid, Policy};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

/// Filter for policy effects when listing policies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum PolicyEffectFilter {
    Any,
    #[default]
    Permit,
    Forbid,
}

/// Why a policy was selected by listing APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyMatchReason {
    PrincipalEq,
    PrincipalIn,
    PrincipalAny,
    PrincipalIs,
    PrincipalIsIn,
    ActionEq,
    ActionIn,
    ActionAny,
    ResourceEq,
    ResourceIn,
    ResourceAny,
    ResourceIs,
    ResourceIsIn,
}

/// Match metadata for one policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PolicyMatch {
    pub cedar_id: String,
    pub reasons: Vec<PolicyMatchReason>,
}

/// Structurally matched candidate policies for a principal.
///
/// This type is not an authorization decision. Its policies have only had
/// their scope constraints matched; Cedar `when` and `unless` clauses have not
/// been evaluated. Use `PolicyEngine::evaluate` to authorize an operation.
#[must_use = "candidate policies are not an authorization decision"]
#[derive(Debug, Clone)]
pub struct UserPolicies {
    user: String,
    policies: Vec<Policy>,
    actions: Vec<EntityUid>,
    matches: Vec<PolicyMatch>,
}

impl UserPolicies {
    pub fn new(user: &str, policies: &[Policy]) -> Self {
        let mut sorted_policies = policies.to_vec();
        sorted_policies.sort_by(|left, right| left.id().cmp(right.id()));

        let matches = sorted_policies
            .iter()
            .map(|p| PolicyMatch {
                cedar_id: p.id().to_string(),
                reasons: Vec::new(),
            })
            .collect();

        Self::new_with_matches_internal(user, sorted_policies, matches)
    }

    pub fn new_with_matches(user: &str, matches: Vec<(Policy, Vec<PolicyMatchReason>)>) -> Self {
        let mut matches = matches;
        matches
            .sort_by(|(left_policy, _), (right_policy, _)| left_policy.id().cmp(right_policy.id()));

        let mut policies = Vec::with_capacity(matches.len());
        let mut policy_matches = Vec::with_capacity(matches.len());
        for (policy, mut reasons) in matches {
            reasons.sort();
            reasons.dedup();
            policy_matches.push(PolicyMatch {
                cedar_id: policy.id().to_string(),
                reasons,
            });
            policies.push(policy);
        }

        Self::new_with_matches_internal(user, policies, policy_matches)
    }

    fn new_with_matches_internal(
        user: &str,
        policies: Vec<Policy>,
        matches: Vec<PolicyMatch>,
    ) -> Self {
        let mut actions = Vec::new();
        for policy in &policies {
            if policy.effect() != cedar_policy::Effect::Permit {
                continue;
            }
            match policy.action_constraint() {
                ActionConstraint::Eq(action) => actions.push(action),
                ActionConstraint::In(actions_in_policy) => actions.extend(actions_in_policy),
                // An unconstrained action cannot be represented as a finite
                // candidate list.
                ActionConstraint::Any => {}
            }
        }
        actions.sort();
        actions.dedup();

        UserPolicies {
            user: user.to_string(),
            policies,
            actions,
            matches,
        }
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Candidate actions mentioned by permit policies.
    ///
    /// Conditions have not been evaluated. This list must not be used to
    /// authorize an operation.
    pub fn candidate_actions(&self) -> &[EntityUid] {
        &self.actions
    }

    /// Backward-compatible alias for [`Self::candidate_actions`].
    ///
    /// This is not a list of authorized actions.
    pub fn actions(&self) -> &[EntityUid] {
        self.candidate_actions()
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    pub fn matches(&self) -> &[PolicyMatch] {
        &self.matches
    }

    /// Whether any candidate has a Cedar `when` or `unless` clause.
    pub fn has_non_scope_constraints(&self) -> bool {
        self.policies.iter().any(Policy::has_non_scope_constraint)
    }

    pub fn reasons_for_policy(&self, cedar_id: &str) -> Option<&[PolicyMatchReason]> {
        self.matches
            .iter()
            .find(|m| m.cedar_id == cedar_id)
            .map(|m| m.reasons.as_slice())
    }

    /// Get the actions as a sorted list of strings.
    pub fn actions_by_name(&self) -> Vec<String> {
        let mut actions = self
            .actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>();
        actions.sort();
        actions
    }

    /// Get the policies as a sorted list of strings.
    pub fn policies_by_name(&self) -> Vec<String> {
        let mut policies = self
            .policies
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>();
        policies.sort();
        policies
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

        let mut s = ser.serialize_struct("UserPolicies", 4)?;
        s.serialize_field("user", &self.user)?;
        s.serialize_field("policies", &policies_as_json)?;
        s.serialize_field("matches", &self.matches)?;
        s.serialize_field(
            "has_non_scope_constraints",
            &self.has_non_scope_constraints(),
        )?;
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
    fn policy_effect_filter_defaults_to_permit() {
        assert_eq!(PolicyEffectFilter::default(), PolicyEffectFilter::Permit);
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
        assert!(json["matches"].is_array());
        assert_eq!(json["matches"].as_array().unwrap().len(), 1);
        assert_eq!(json["has_non_scope_constraints"], false);
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

    #[test]
    fn test_user_policies_with_match_reasons() {
        let policy_text =
            r#"permit(principal == User::"alice", action == Action::"read", resource);"#;
        let policy = Policy::parse(None, policy_text).unwrap();

        let policies = UserPolicies::new_with_matches(
            "alice",
            vec![(
                policy,
                vec![
                    PolicyMatchReason::PrincipalEq,
                    PolicyMatchReason::ResourceAny,
                    PolicyMatchReason::PrincipalEq,
                ],
            )],
        );

        assert_eq!(policies.matches().len(), 1);
        let reasons = &policies.matches()[0].reasons;
        assert_eq!(reasons.len(), 2);
        assert!(reasons.contains(&PolicyMatchReason::PrincipalEq));
        assert!(reasons.contains(&PolicyMatchReason::ResourceAny));
    }
}
