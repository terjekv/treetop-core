//! Helpers for constructing Cedar `EntityUid` values from API-style inputs.

use cedar_policy::{EntityId, EntityTypeName, EntityUid};

use crate::error::PolicyError;

fn typed_entity_uid(
    id: &str,
    namespace: &[&str],
    entity_type: &str,
) -> Result<EntityUid, PolicyError> {
    if id.is_empty() {
        return Err(PolicyError::InvalidFormat(
            "entity identifier cannot be empty".to_string(),
        ));
    }

    let type_name = if namespace.is_empty() {
        entity_type.to_string()
    } else {
        let capacity = namespace
            .iter()
            .try_fold(entity_type.len(), |length, segment| {
                length
                    .checked_add(2)
                    .and_then(|length| length.checked_add(segment.len()))
            })
            .ok_or_else(|| {
                PolicyError::InvalidFormat("Cedar entity type is too long".to_string())
            })?;
        let mut type_name = String::with_capacity(capacity);
        for (index, segment) in namespace.iter().enumerate() {
            if index > 0 {
                type_name.push_str("::");
            }
            type_name.push_str(segment);
        }
        type_name.push_str("::");
        type_name.push_str(entity_type);
        type_name
    };
    let type_name: EntityTypeName = type_name.parse().map_err(|error| {
        PolicyError::InvalidFormat(format!("invalid Cedar entity type '{type_name}': {error}"))
    })?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

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
    typed_entity_uid(user, namespace, "User")
}

/// Build a group `EntityUid` from an id + optional namespace.
pub fn group_entity_uid(group: &str, namespace: &[&str]) -> Result<EntityUid, PolicyError> {
    typed_entity_uid(group, namespace, "Group")
}

/// Build an action `EntityUid` from an id + optional namespace.
pub fn action_entity_uid(action: &str, namespace: &[&str]) -> Result<EntityUid, PolicyError> {
    typed_entity_uid(action, namespace, "Action")
}

/// Build a resource `EntityUid` from a kind + id pair.
pub fn resource_entity_uid(kind: &str, resource_id: &str) -> Result<EntityUid, PolicyError> {
    if resource_id.is_empty() {
        return Err(PolicyError::InvalidFormat(
            "resource identifier cannot be empty".to_string(),
        ));
    }
    let type_name: EntityTypeName = kind.parse().map_err(|error| {
        PolicyError::InvalidFormat(format!("invalid resource type '{kind}': {error}"))
    })?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(resource_id),
    ))
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

    #[test]
    fn typed_uid_helpers_reject_empty_ids() {
        assert!(user_entity_uid("", &[]).is_err());
        assert!(group_entity_uid("", &[]).is_err());
        assert!(action_entity_uid("", &[]).is_err());
        assert!(resource_entity_uid("Host", "").is_err());
    }

    #[test]
    fn typed_uid_helpers_reject_invalid_types() {
        assert!(user_entity_uid("alice", &["invalid namespace"]).is_err());
        assert!(resource_entity_uid("invalid type", "web-01").is_err());
    }

    #[test]
    fn typed_uid_helpers_preserve_special_ids() {
        let uid = action_entity_uid("read::\"archive\"", &["App", "Core"]).unwrap();
        assert_eq!(uid.id().unescaped(), "read::\"archive\"");
        assert_eq!(uid.type_name().to_string(), "App::Core::Action");
    }
}
