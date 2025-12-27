//! Qualified identifiers for Cedar entities with namespace support.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
}

impl<T> QualifiedId<T> {
    /// Construct from its parts.  Guaranteed valid by signature.
    pub fn new(id: impl Into<String>, namespace: Option<Vec<String>>) -> Self {
        QualifiedId {
            id: id.into(),
            namespace: namespace.unwrap_or_default(),
            _marker: PhantomData,
        }
    }

    /// Get the raw id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the namespace path.
    #[allow(dead_code)]
    pub fn namespace(&self) -> &[String] {
        &self.namespace
    }

    /// Render as `"Ns1::Ns2::Type::"id""`.
    pub fn fmt_qualified(&self, ty: &str) -> String {
        let mut parts = self.namespace.join("::");
        if !parts.is_empty() {
            parts.push_str("::");
        }
        format!(
            r#"{parts}{ty}::"{id}""#,
            id = self.id,
            parts = parts,
            ty = ty
        )
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
        let id: UserId = QualifiedId::new("alice", Some(vec!["App".to_string(), "Core".to_string()]));
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
        let id: ActionId = QualifiedId::new("delete", Some(vec!["App".to_string(), "Admin".to_string(), "Actions".to_string()]));
        assert_eq!(id.fmt_qualified("Action"), r#"App::Admin::Actions::Action::"delete""#);
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
    fn test_qualified_id_empty_id() {
        let id: UserId = QualifiedId::new("", None);
        assert_eq!(id.id(), "");
    }

    #[test]
    fn test_qualified_id_from_string() {
        let id: UserId = QualifiedId::new("alice".to_string(), None);
        assert_eq!(id.id(), "alice");
    }
}
