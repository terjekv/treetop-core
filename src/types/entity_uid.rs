//! Helpers for constructing Cedar `EntityUid` values from API-style inputs.

use cedar_policy::EntityUid;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::{Action, Group, Resource, User};

/// Convert `&[&str]` namespace segments (used by listing APIs) into owned namespace vectors.
pub fn namespace_segments(namespace: &[&str]) -> Option<Vec<String>> {
    if namespace.is_empty() {
        return None;
    }
    Some(
        namespace
            .iter()
            .map(|segment| segment.to_string())
            .collect(),
    )
}

/// Build a user `EntityUid` from an id + optional namespace.
pub fn user_entity_uid(user: &str, namespace: &[&str]) -> Result<EntityUid, PolicyError> {
    User::new(user, None, namespace_segments(namespace)).cedar_entity_uid()
}

/// Build a group `EntityUid` from an id + optional namespace.
pub fn group_entity_uid(group: &str, namespace: &[&str]) -> Result<EntityUid, PolicyError> {
    Group::new(group, namespace_segments(namespace)).cedar_entity_uid()
}

/// Build an action `EntityUid` from an id + optional namespace.
pub fn action_entity_uid(action: &str, namespace: &[&str]) -> Result<EntityUid, PolicyError> {
    Action::new(action, namespace_segments(namespace)).cedar_entity_uid()
}

/// Build a resource `EntityUid` from a kind + id pair.
pub fn resource_entity_uid(kind: &str, resource_id: &str) -> Result<EntityUid, PolicyError> {
    Resource::new(kind, resource_id).cedar_entity_uid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_segments_empty() {
        assert!(namespace_segments(&[]).is_none());
    }

    #[test]
    fn test_namespace_segments_non_empty() {
        let ns = namespace_segments(&["Infra", "Core"]).unwrap();
        assert_eq!(ns, vec!["Infra".to_string(), "Core".to_string()]);
    }

    #[test]
    fn test_user_entity_uid() {
        let uid = user_entity_uid("alice", &["App"]).unwrap();
        assert_eq!(uid.to_string(), r#"App::User::"alice""#);
    }

    #[test]
    fn test_group_entity_uid() {
        let uid = group_entity_uid("admins", &[]).unwrap();
        assert_eq!(uid.to_string(), r#"Group::"admins""#);
    }
}
