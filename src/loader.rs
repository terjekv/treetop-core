use crate::error::PolicyError;
use cedar_policy::{ParseErrors, PolicySet};

pub fn compile_policy(text: &str) -> Result<PolicySet, PolicyError> {
    text.parse()
        .map_err(|e: ParseErrors| PolicyError::ParseError(e.to_string()))
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
