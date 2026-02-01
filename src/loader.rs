use std::collections::HashMap;

use crate::error::PolicyError;
use crate::types::PermitPolicy;
use cedar_policy::{ParseErrors, PolicyId, PolicySet};

/// Compile Cedar policy text into a `PolicySet`.
///
/// Any Cedar parse errors are mapped into `PolicyError::ParseError`.
///
/// Example:
/// ```rust
/// use treetop_core::compile_policy;
/// let policy_text = r#"
///     permit (principal, action, resource);
///     forbid  (principal == User::"evil", action, resource);
/// "#;
/// let set = compile_policy(policy_text).unwrap();
/// assert!(set.num_of_policies() >= 1);
/// ```
pub fn compile_policy(text: &str) -> Result<PolicySet, PolicyError> {
    text.parse()
        .map_err(|e: ParseErrors| PolicyError::ParseError(e.to_string()))
}

/// Precompute permit policy metadata for fast lookup during evaluation.
pub fn precompute_permit_policies(set: &PolicySet) -> HashMap<PolicyId, PermitPolicy> {
    set.policies()
        .map(|policy| {
            let permit_policy = PermitPolicy::new(
                policy.to_string(),
                policy.to_json().unwrap_or_default(),
                policy.id().to_string(),
            );
            (policy.id().clone(), permit_policy)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_policy() {
        let policy_text = r#"
            permit (principal == User::"alice", action == Action::"read", resource == Document::"doc1");
            permit (principal == User::"bob", action == Action::"write", resource == Document::"doc2");
        "#;
        let policy_set = compile_policy(policy_text);
        assert!(policy_set.is_ok());
        let policy_set = policy_set.unwrap();
        assert_eq!(policy_set.num_of_policies(), 2);
    }
}
