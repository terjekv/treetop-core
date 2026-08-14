//! Qualified identifiers for Cedar entities with namespace support.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use cedar_policy::{EntityId, EntityTypeName, EntityUid};

use crate::error::PolicyError;

use super::uid_cache::EntityUidCache;

/// Marker type for Users
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum UserMarker {}

/// Marker type for Group
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum GroupMarker {}

/// Marker type for Actions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum ActionMarker {}

/// A fully‐qualified identifier, with zero runtime cost over `(Vec<String>, String)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct QualifiedId<T> {
    id: String,
    namespace: Vec<String>,
    #[serde(skip)]
    _marker: PhantomData<T>,
    #[serde(skip)]
    uid_cache: EntityUidCache,
}

impl<T> QualifiedId<T> {
    /// Construct from its parts.
    ///
    /// Validation is performed when converting to a Cedar entity UID. Prefer
    /// [`Self::try_new`] at an untrusted input boundary.
    pub fn new(id: impl Into<String>, namespace: Option<Vec<String>>) -> Self {
        QualifiedId {
            id: id.into(),
            namespace: namespace.unwrap_or_default(),
            _marker: PhantomData,
            uid_cache: EntityUidCache::default(),
        }
    }

    /// Construct a non-empty identifier with a valid Cedar namespace.
    pub fn try_new(
        id: impl Into<String>,
        namespace: Option<Vec<String>>,
    ) -> Result<Self, PolicyError> {
        let qualified = Self::new(id, namespace);
        qualified.validate_namespace_with_type("Entity")?;
        if qualified.id.is_empty() {
            return Err(PolicyError::InvalidFormat(
                "entity identifier cannot be empty".to_string(),
            ));
        }
        Ok(qualified)
    }

    /// Get the raw id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the namespace path.
    pub fn namespace(&self) -> &[String] {
        &self.namespace
    }

    /// Render as `"Ns1::Ns2::Type::"id""`.
    pub fn fmt_qualified(&self, ty: &str) -> String {
        let mut parts = self.namespace.join("::");
        if !parts.is_empty() {
            parts.push_str("::");
        }
        let escaped = EntityId::new(&self.id).escaped();
        format!(r#"{parts}{ty}::"{escaped}""#)
    }

    pub(crate) fn cedar_entity_uid(&self, ty: &str) -> Result<EntityUid, PolicyError> {
        self.uid_cache.get_or_build(|| {
            if self.id.is_empty() {
                return Err(PolicyError::InvalidFormat(
                    "entity identifier cannot be empty".to_string(),
                ));
            }
            let type_name = self.validate_namespace_with_type(ty)?;
            Ok(EntityUid::from_type_name_and_id(
                type_name,
                EntityId::new(&self.id),
            ))
        })
    }

    fn validate_namespace_with_type(&self, ty: &str) -> Result<EntityTypeName, PolicyError> {
        let type_name = if self.namespace.is_empty() {
            ty.to_string()
        } else {
            format!("{}::{ty}", self.namespace.join("::"))
        };
        type_name.parse().map_err(|e| {
            PolicyError::InvalidFormat(format!("invalid Cedar entity type '{type_name}': {e}"))
        })
    }
}

impl<T> Display for QualifiedId<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // We don't know `T`'s name here; we'll implement Display on the wrappers.
        write!(f, "{}", self.id)
    }
}

/// A User's fully‐qualified ID.
pub type UserId = QualifiedId<UserMarker>;

/// A Group's fully‐qualified ID.
pub type GroupId = QualifiedId<GroupMarker>;

/// An Action's fully‐qualified ID.
pub type ActionId = QualifiedId<ActionMarker>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_qualified_id_display() {
        let id: UserId = QualifiedId::new("alice", None);
        assert_eq!(format!("{}", id), "alice");
    }

    #[test]
    fn test_qualified_id_fmt_qualified() {
        let id: UserId = QualifiedId::new("alice", Some(vec!["Infra".to_string()]));
        assert_eq!(id.fmt_qualified("User"), r#"Infra::User::"alice""#);
    }

    #[test]
    fn test_qualified_id_namespace_accessor() {
        let id: UserId =
            QualifiedId::new("alice", Some(vec!["App".to_string(), "Core".to_string()]));
        assert_eq!(id.namespace(), &["App".to_string(), "Core".to_string()]);
    }

    #[test]
    fn test_qualified_id_empty_namespace() {
        let id: UserId = QualifiedId::new("alice", None);
        assert_eq!(id.namespace(), &[] as &[String]);
        assert_eq!(id.fmt_qualified("User"), r#"User::"alice""#);
    }

    #[test]
    fn test_qualified_id_multiple_namespaces() {
        let id: ActionId = QualifiedId::new(
            "delete",
            Some(vec![
                "App".to_string(),
                "Admin".to_string(),
                "Actions".to_string(),
            ]),
        );
        assert_eq!(
            id.fmt_qualified("Action"),
            r#"App::Admin::Actions::Action::"delete""#
        );
    }

    #[test]
    fn test_qualified_id_with_special_chars() {
        let id: UserId = QualifiedId::new("alice@example.com", None);
        assert_eq!(id.id(), "alice@example.com");
    }

    #[test]
    fn test_qualified_id_types() {
        let user_id: UserId = QualifiedId::new("alice", None);
        let group_id: GroupId = QualifiedId::new("admins", None);
        let action_id: ActionId = QualifiedId::new("read", None);

        assert_eq!(user_id.id(), "alice");
        assert_eq!(group_id.id(), "admins");
        assert_eq!(action_id.id(), "read");
    }

    #[test]
    fn test_qualified_id_clone() {
        let original: UserId = QualifiedId::new("alice", Some(vec!["App".to_string()]));
        let cloned = original.clone();
        assert_eq!(original.id(), cloned.id());
        assert_eq!(original.namespace(), cloned.namespace());
    }

    #[test]
    fn test_qualified_id_serialization() {
        let id: UserId = QualifiedId::new("alice", Some(vec!["App".to_string()]));
        let serialized = serde_json::to_value(&id).unwrap();
        let deserialized: UserId = serde_json::from_value(serialized).unwrap();
        assert_eq!(id.id(), deserialized.id());
        assert_eq!(id.namespace(), deserialized.namespace());
    }

    #[test]
    fn cached_uid_does_not_change_value_semantics() {
        let cached: UserId = QualifiedId::new("alice", Some(vec!["App".to_string()]));
        let uncached = cached.clone();
        cached.cedar_entity_uid("User").unwrap();

        assert_eq!(cached, uncached);
        assert_eq!(
            serde_json::to_value(&cached).unwrap(),
            serde_json::to_value(&uncached).unwrap()
        );

        let mut cached_hasher = DefaultHasher::new();
        cached.hash(&mut cached_hasher);
        let mut uncached_hasher = DefaultHasher::new();
        uncached.hash(&mut uncached_hasher);
        assert_eq!(cached_hasher.finish(), uncached_hasher.finish());
    }

    #[test]
    fn cached_uid_initialization_is_thread_safe() {
        let id = Arc::new(UserId::new(
            "alice",
            Some(vec!["App".to_string(), "Core".to_string()]),
        ));
        let handles = (0..8)
            .map(|_| {
                let id = Arc::clone(&id);
                thread::spawn(move || id.cedar_entity_uid("User").unwrap())
            })
            .collect::<Vec<_>>();

        for handle in handles {
            assert_eq!(
                handle.join().unwrap().to_string(),
                r#"App::Core::User::"alice""#
            );
        }
    }

    #[test]
    fn test_qualified_id_empty_id() {
        let id: UserId = QualifiedId::new("", None);
        assert_eq!(id.id(), "");
        assert!(id.cedar_entity_uid("User").is_err());
    }

    #[test]
    fn test_qualified_id_escapes_entity_id() {
        let id: UserId = QualifiedId::try_new("a\"b\\c", None).unwrap();
        assert_eq!(id.fmt_qualified("User"), r#"User::"a\"b\\c""#);
        assert_eq!(
            id.cedar_entity_uid("User").unwrap().id().unescaped(),
            "a\"b\\c"
        );
    }

    #[test]
    fn test_qualified_id_try_new_rejects_invalid_namespace() {
        let result: Result<UserId, _> =
            QualifiedId::try_new("alice", Some(vec!["invalid namespace".into()]));
        assert!(result.is_err());
    }

    #[test]
    fn test_qualified_id_from_string() {
        let id: UserId = QualifiedId::new("alice".to_string(), None);
        assert_eq!(id.id(), "alice");
    }
}
