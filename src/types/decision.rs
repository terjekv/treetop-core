//! Authorization decision types with policy metadata.

use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// A permit policy that permitted a specific action on a resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default, ToSchema)]
pub struct PermitPolicy {
    pub literal: String,
    pub json: Value,
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
        policy: PermitPolicy,
        version: PolicyVersion,
    },
    Deny {
        version: PolicyVersion,
    },
}

impl Display for Decision {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Decision::Allow { policy, version } => {
                write!(f, "Allow(hash={}; {})", version.hash, policy.literal)
            }
            Decision::Deny { version } => write!(f, "Deny(hash={})", version.hash),
        }
    }
}

pub trait FromDecisionWithPolicy {
    fn from_decision_with_policy(
        response: cedar_policy::Decision,
        policy: PermitPolicy,
        version: PolicyVersion,
    ) -> Self;
}

impl FromDecisionWithPolicy for Decision {
    fn from_decision_with_policy(
        decision: cedar_policy::Decision,
        policy: PermitPolicy,
        version: PolicyVersion,
    ) -> Self {
        match decision {
            cedar_policy::Decision::Allow => Decision::Allow { policy, version },
            cedar_policy::Decision::Deny => Decision::Deny { version },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_display_allow() {
        let policy = PermitPolicy {
            literal: "permit(principal, action, resource);".to_string(),
            json: serde_json::json!({"effect": "permit"}),
        };
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };
        let decision = Decision::Allow {
            policy: policy.clone(),
            version: version.clone(),
        };
        let display = format!("{}", decision);
        assert!(display.contains("Allow"));
        assert!(display.contains("abc123"));
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
        let policy = PermitPolicy {
            literal: "permit(principal, action, resource);".to_string(),
            json: serde_json::json!({"effect": "permit"}),
        };
        let version = PolicyVersion {
            hash: "test123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let decision = Decision::from_decision_with_policy(
            cedar_policy::Decision::Allow,
            policy.clone(),
            version.clone(),
        );

        match decision {
            Decision::Allow {
                policy: p,
                version: v,
            } => {
                assert_eq!(p.literal, policy.literal);
                assert_eq!(v.hash, version.hash);
            }
            _ => panic!("Expected Allow decision"),
        }
    }

    #[test]
    fn test_from_decision_with_policy_deny() {
        let policy = PermitPolicy::default();
        let version = PolicyVersion {
            hash: "test123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let decision = Decision::from_decision_with_policy(
            cedar_policy::Decision::Deny,
            policy,
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
    fn test_permit_policy_default() {
        let policy = PermitPolicy::default();
        assert_eq!(policy.literal, "");
        assert!(policy.json.is_null());
    }

    #[test]
    fn test_decision_serialization() {
        let policy = PermitPolicy {
            literal: "permit(principal, action, resource);".to_string(),
            json: serde_json::json!({"effect": "permit"}),
        };
        let version = PolicyVersion {
            hash: "abc123".to_string(),
            loaded_at: "2023-01-01T00:00:00Z".to_string(),
        };

        let decision = Decision::Allow { policy, version };
        let serialized = serde_json::to_value(&decision).unwrap();
        let deserialized: Decision = serde_json::from_value(serialized).unwrap();

        match deserialized {
            Decision::Allow { version: v, .. } => {
                assert_eq!(v.hash, "abc123");
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
        let policy = PermitPolicy {
            literal: "test".to_string(),
            json: serde_json::json!({"test": "value"}),
        };
        let cloned = policy.clone();
        assert_eq!(policy.literal, cloned.literal);
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
}
