//! Authorization decision types with policy metadata.

use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// A permit policy that permitted a specific action on a resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub struct PermitPolicy {
    pub literal: String,
    pub json: Value,
    pub annotation_id: Option<String>,
    pub cedar_id: String,
}

impl PermitPolicy {
    pub fn new(literal: String, json: Value, cedar_id: String) -> Self {
        let annotation_id = Self::extract_annotation_id(&literal, &json);
        Self {
            literal,
            json,
            annotation_id,
            cedar_id,
        }
    }

    /// Returns the ID of the policy if available.
    ///
    /// IDs should be in annotations > id field in the JSON representation, or an @id line in the literal.
    pub fn id(&self) -> &String {
        match &self.annotation_id {
            Some(id) => id,
            None => &self.cedar_id,
        }
    }

    fn extract_annotation_id(literal: &str, json: &Value) -> Option<String> {
        if let Some(annotations) = json.get("annotations")
            && let Some(id_value) = annotations.get("id")
            && let Some(id_str) = id_value.as_str()
        {
            return Some(id_str.to_string());
        }

        for line in literal.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("@id") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].trim_end_matches(';').to_string());
                }
            }
        }

        None
    }
}

/// A collection of permit policies with optimized access patterns.
///
/// This wrapper provides efficient methods for common operations like
/// displaying policies, extracting IDs, and iterating over policies.
///
/// Serializes as a flat array instead of a nested object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
#[serde(transparent)]
pub struct PermitPolicies(Vec<PermitPolicy>);

impl PermitPolicies {
    /// Create a new collection from a vector of policies.
    pub fn new(policies: Vec<PermitPolicy>) -> Self {
        Self(policies)
    }

    /// Create an empty collection.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of policies in this collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get policy IDs as a sorted vector of strings.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.0.iter().map(|p| p.id().clone()).collect();
        ids.sort();
        ids
    }

    /// Get an iterator over the policies.
    pub fn iter(&self) -> impl Iterator<Item = &PermitPolicy> {
        self.0.iter()
    }

    /// Consume self and return the inner vector of policies.
    pub fn into_inner(self) -> Vec<PermitPolicy> {
        self.0
    }

    /// Get a reference to the inner vector of policies.
    pub fn as_slice(&self) -> &[PermitPolicy] {
        &self.0
    }
}

impl Display for PermitPolicies {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Get sorted literals for consistent display
        let mut literals: Vec<&str> = self.0.iter().map(|p| p.literal.as_str()).collect();
        literals.sort();
        write!(f, "{}", literals.join("; "))
    }
}

impl IntoIterator for PermitPolicies {
    type Item = PermitPolicy;
    type IntoIter = std::vec::IntoIter<PermitPolicy>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a PermitPolicies {
    type Item = &'a PermitPolicy;
    type IntoIter = std::slice::Iter<'a, PermitPolicy>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<Vec<PermitPolicy>> for PermitPolicies {
    fn from(policies: Vec<PermitPolicy>) -> Self {
        Self::new(policies)
    }
}

impl FromIterator<PermitPolicy> for PermitPolicies {
    fn from_iter<I: IntoIterator<Item = PermitPolicy>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

/// Version metadata for the policy set used during an evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub struct PolicyVersion {
    /// Hash of the policy source (e.g. SHA-256 of the policy text).
    pub hash: String,
    /// When this policy set was loaded into the engine.
    pub loaded_at: String,
}

impl Display for PolicyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} @ {}", self.hash, self.loaded_at)
    }
}

/// Allow or deny decision, including the policy version used.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub enum Decision {
    Allow {
        policies: PermitPolicies,
        version: PolicyVersion,
    },
    Deny {
        version: PolicyVersion,
    },
}

/// Authorization decision plus deny-side forbid diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub struct DecisionDiagnostics {
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_forbid_policy_ids: Vec<String>,
}

impl Display for Decision {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Decision::Allow { policies, version } => {
                write!(f, "Allow(hash={}; [{}])", version.hash, policies)
            }
            Decision::Deny { version } => write!(f, "Deny(hash={})", version.hash),
        }
    }
}

pub trait FromDecisionWithPolicy {
    fn from_decision_with_policy(
        response: cedar_policy::Decision,
        policies: PermitPolicies,
        version: PolicyVersion,
    ) -> Self;
}

impl FromDecisionWithPolicy for Decision {
    fn from_decision_with_policy(
        decision: cedar_policy::Decision,
        policies: PermitPolicies,
        version: PolicyVersion,
    ) -> Self {
        match decision {
            cedar_policy::Decision::Allow => {
                if policies.is_empty() {
                    panic!("Allow decision must have at least one policy");
                }
                Decision::Allow { policies, version }
            }
            cedar_policy::Decision::Deny => Decision::Deny { version },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_display_allow() {
        let policy = PermitPolicy::new(
            "permit(principal, action, resource);".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy0".to_string(),
        );
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };
        let decision = Decision::Allow {
            policies: vec![policy.clone()].into(),
            version: version.clone(),
        };
        let display = format!("{}", decision);
        assert!(display.contains("Allow"));
        assert!(display.contains("abc123"));
        assert!(display.contains("permit(principal, action, resource);"));
    }

    #[test]
    fn test_decision_display_deny() {
        let version = PolicyVersion {
            hash: "def456".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };
        let decision = Decision::Deny { version };
        let display = format!("{}", decision);
        assert!(display.contains("Deny"));
        assert!(display.contains("def456"));
    }

    #[test]
    fn test_policy_version_display() {
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };
        let display = format!("{}", version);
        assert!(display.contains("abc123"));
        assert!(display.contains("2023-01-01T00:00:00Z"));
    }

    #[test]
    fn test_from_decision_with_policy_allow() {
        let policy = PermitPolicy::new(
            "permit(principal, action, resource);".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy0".to_string(),
        );
        let version = PolicyVersion {
            hash: "test123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let decision = Decision::from_decision_with_policy(
            cedar_policy::Decision::Allow,
            vec![policy.clone()].into(),
            version.clone(),
        );

        match decision {
            Decision::Allow {
                policies,
                version: v,
            } => {
                assert_eq!(policies.len(), 1);
                let first_policy = policies.as_slice()[0].clone();
                assert_eq!(first_policy.literal, policy.literal);
                assert_eq!(first_policy.cedar_id, "policy0".to_string());
                assert_eq!(v.hash, version.hash);
            }
            _ => panic!("Expected Allow decision"),
        }
    }

    #[test]
    fn test_from_decision_with_policy_deny() {
        let version = PolicyVersion {
            hash: "test123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let decision = Decision::from_decision_with_policy(
            cedar_policy::Decision::Deny,
            PermitPolicies::empty(),
            version.clone(),
        );

        match decision {
            Decision::Deny { version: v } => {
                assert_eq!(v.hash, version.hash);
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_permit_policy_construction() {
        let policy = PermitPolicy::new(
            "permit(principal, action, resource);".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy0".to_string(),
        );
        assert_eq!(policy.literal, "permit(principal, action, resource);");
        assert_eq!(policy.cedar_id, "policy0".to_string());
    }

    #[test]
    fn test_decision_serialization() {
        let policy = PermitPolicy::new(
            "permit(principal, action, resource);".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy0".to_string(),
        );
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let decision = Decision::Allow {
            policies: vec![policy].into(),
            version,
        };
        let serialized = serde_json::to_value(&decision).unwrap();

        // Verify that policy metadata is included in serialization
        // PermitPolicies is transparent, so it serializes as a flat array
        let allow_obj = serialized.get("Allow");
        assert!(allow_obj.is_some());
        let policies_arr = allow_obj.and_then(|a| a.get("policies"));
        assert!(policies_arr.is_some());
        assert!(policies_arr.unwrap().is_array());

        let deserialized: Decision = serde_json::from_value(serialized).unwrap();

        match deserialized {
            Decision::Allow {
                version: v,
                policies,
            } => {
                assert_eq!(v.hash, "abc123");
                assert_eq!(policies.len(), 1);
                let first_policy = policies.as_slice()[0].clone();
                assert_eq!(first_policy.cedar_id, "policy0".to_string());
            }
            _ => panic!("Expected Allow decision"),
        }
    }

    #[test]
    fn test_policy_version_serialization() {
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let serialized = serde_json::to_value(&version).unwrap();
        let deserialized: PolicyVersion = serde_json::from_value(serialized).unwrap();

        assert_eq!(version.hash, deserialized.hash);
        assert_eq!(version.loaded_at, deserialized.loaded_at);
    }

    #[test]
    fn test_permit_policy_clone() {
        let policy = PermitPolicy::new(
            "test".to_string(),
            serde_json::json!({"test": "value"}),
            "policy1".to_string(),
        );
        let cloned = policy.clone();
        assert_eq!(policy.literal, cloned.literal);
        assert_eq!(policy.cedar_id, cloned.cedar_id);
        assert_eq!(policy.cedar_id, "policy1".to_string());
    }

    #[test]
    fn test_decision_clone() {
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };
        let decision = Decision::Deny { version };
        let cloned = decision.clone();

        match cloned {
            Decision::Deny { version: v } => {
                assert_eq!(v.hash, "abc123");
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_permit_policies_display() {
        let policy1 = PermitPolicy::new(
            "permit(principal, action, resource == File::\"z.txt\");".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy_z".to_string(),
        );
        let policy2 = PermitPolicy::new(
            "permit(principal, action, resource == File::\"a.txt\");".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy_a".to_string(),
        );

        // Add policies in reverse alphabetical order
        let policies = PermitPolicies::new(vec![policy1, policy2]);

        // Display should sort them alphabetically
        let display = format!("{}", policies);
        assert!(display.starts_with("permit(principal, action, resource == File::\"a.txt\");"));
        assert!(display.contains("; "));
        assert!(display.ends_with("permit(principal, action, resource == File::\"z.txt\");"));
    }

    #[test]
    fn test_permit_policies_ids() {
        let policy1 = PermitPolicy::new(
            "test1".to_string(),
            serde_json::json!({}),
            "policy_z".to_string(),
        );
        let policy2 = PermitPolicy::new(
            "test2".to_string(),
            serde_json::json!({}),
            "policy_a".to_string(),
        );

        // Add policies in reverse alphabetical order
        let policies = PermitPolicies::new(vec![policy1, policy2]);

        // ids() should return sorted IDs
        let ids = policies.ids();
        assert_eq!(ids, vec!["policy_a", "policy_z"]);
    }

    #[test]
    fn test_permit_policies_iteration() {
        let policy1 = PermitPolicy::new(
            "test1".to_string(),
            serde_json::json!({}),
            "policy1".to_string(),
        );
        let policy2 = PermitPolicy::new(
            "test2".to_string(),
            serde_json::json!({}),
            "policy2".to_string(),
        );

        let policies = PermitPolicies::new(vec![policy1.clone(), policy2.clone()]);

        // Test reference iteration
        let mut count = 0;
        for policy in &policies {
            count += 1;
            assert!(policy.cedar_id == "policy1" || policy.cedar_id == "policy2");
        }
        assert_eq!(count, 2);

        // Test consuming iteration
        let collected: Vec<_> = policies.into_iter().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].cedar_id, policy1.cedar_id);
        assert_eq!(collected[1].cedar_id, policy2.cedar_id);
    }

    #[test]
    fn test_decision_diagnostics_serialization() {
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };
        let diagnostics = DecisionDiagnostics {
            decision: Decision::Deny { version },
            matched_forbid_policy_ids: vec!["deny_delete".to_string()],
        };

        let serialized = serde_json::to_value(&diagnostics).unwrap();
        assert_eq!(serialized["matched_forbid_policy_ids"][0], "deny_delete");
    }
}
