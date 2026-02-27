use std::collections::HashMap;

use crate::error::PolicyError;
use crate::types::PermitPolicy;
use cedar_policy::{Effect, ParseErrors, PolicyId, PolicySet, Schema, ValidationMode, Validator};

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

/// Compile Cedar policy text into a `PolicySet` and validate against a schema.
///
/// Any Cedar parse errors are mapped into `PolicyError::ParseError`.
/// Validation failures are also mapped into `PolicyError::ParseError`.
pub fn compile_policy_with_schema(text: &str, schema: &Schema) -> Result<PolicySet, PolicyError> {
    let set = compile_policy(text)?;
    validate_policy_set_with_schema(&set, schema)?;
    Ok(set)
}

/// Validate an already-compiled policy set against a schema.
pub fn validate_policy_set_with_schema(
    set: &PolicySet,
    schema: &Schema,
) -> Result<(), PolicyError> {
    let validator = Validator::new(schema.clone());
    let result = validator.validate(set, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(());
    }

    Err(PolicyError::ParseError(format!(
        "policy failed schema validation: {result}"
    )))
}

/// Precompute permit policy metadata for fast lookup during evaluation.
pub fn precompute_permit_policies(set: &PolicySet) -> HashMap<PolicyId, PermitPolicy> {
    set.policies()
        .filter(|policy| policy.effect() == Effect::Permit)
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

/// Precompute best available policy IDs for all forbid policies.
///
/// For each forbid policy this prefers `@id(...)` when available, otherwise
/// falls back to Cedar's internal policy ID (e.g. `policy3`).
pub fn precompute_forbid_policy_ids(set: &PolicySet) -> HashMap<PolicyId, String> {
    set.policies()
        .filter(|policy| policy.effect() == Effect::Forbid)
        .map(|policy| {
            let best_id = policy
                .annotation("id")
                .map(ToString::to_string)
                .unwrap_or_else(|| policy.id().to_string());
            (policy.id().clone(), best_id)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::Schema;

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

    #[test]
    fn test_compile_policy_with_schema() {
        let schema: Schema = r#"
            entity User;
            entity Document;
            action "read" appliesTo {
                principal: [User],
                resource: [Document],
            };
        "#
        .parse()
        .unwrap();

        let policy_text = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let policy_set = compile_policy_with_schema(policy_text, &schema);
        assert!(policy_set.is_ok());
    }

    #[test]
    fn test_compile_policy_with_schema_rejects_invalid_policy() {
        let schema: Schema = r#"
            entity User;
            entity Document;
            action "read" appliesTo {
                principal: [User],
                resource: [Document],
            };
        "#
        .parse()
        .unwrap();

        let policy_text = r#"
            permit (
                principal == User::"alice",
                action == Action::"write",
                resource == Document::"doc1"
            );
        "#;

        let policy_set = compile_policy_with_schema(policy_text, &schema);
        assert!(matches!(policy_set, Err(PolicyError::ParseError(_))));
    }

    #[test]
    fn test_precompute_forbid_policy_ids_prefers_annotation_id() {
        let policy_text = r#"
            @id("deny_delete")
            forbid (principal, action == Action::"delete", resource);
            forbid (principal, action == Action::"edit", resource);
        "#;
        let set = compile_policy(policy_text).unwrap();
        let ids = precompute_forbid_policy_ids(&set);
        let values = ids.values().cloned().collect::<Vec<_>>();
        assert!(values.iter().any(|id| id == "deny_delete"));
        assert!(values.iter().any(|id| id.starts_with("policy")));
    }
}
