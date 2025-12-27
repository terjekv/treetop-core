//! Principal type that can be either a User or a Group.

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

use cedar_policy::{Context, EntityUid, RestrictedExpression};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::cedar_type::CedarType;
use super::group::Group;
use super::user::User;

/// A principal for a policy query.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub enum Principal {
    User(User),
    Group(Group),
}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Principal::User(user) => write!(f, "{user}"),
            Principal::Group(group) => write!(f, "{group}"),
        }
    }
}

/// Dispatch the CedarAtom trait to the correct type.
impl CedarAtom for Principal {
    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        match self {
            Principal::User(user) => user.cedar_entity_uid(),
            Principal::Group(group) => group.cedar_entity_uid(),
        }
    }

    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        match self {
            Principal::User(user) => user.cedar_attr(),
            Principal::Group(group) => group.cedar_attr(),
        }
    }

    fn cedar_ctx(&self) -> Result<Context, PolicyError> {
        match self {
            Principal::User(user) => user.cedar_ctx(),
            Principal::Group(group) => group.cedar_ctx(),
        }
    }

    fn cedar_type() -> &'static str {
        CedarType::Principal.as_ref()
    }

    fn cedar_id(&self) -> String {
        match self {
            Principal::User(user) => user.cedar_id(),
            Principal::Group(group) => group.cedar_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CedarAtom;

    #[test]
    fn test_principal_display_user() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        assert_eq!(format!("{}", principal), r#"User::"alice""#);
    }

    #[test]
    fn test_principal_display_group() {
        let group = Group::new("admins", None);
        let principal = Principal::Group(group);
        assert_eq!(format!("{}", principal), r#"Group::"admins""#);
    }

    #[test]
    fn test_principal_cedar_id_user() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        assert_eq!(principal.cedar_id(), r#"User::"alice""#);
    }

    #[test]
    fn test_principal_cedar_id_group() {
        let group = Group::new("admins", None);
        let principal = Principal::Group(group);
        assert_eq!(principal.cedar_id(), r#"Group::"admins""#);
    }

    #[test]
    fn test_principal_cedar_type() {
        assert_eq!(Principal::cedar_type(), "Principal");
    }

    #[test]
    fn test_principal_cedar_entity_uid_user() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        let entity_uid = principal.cedar_entity_uid().unwrap();
        assert_eq!(entity_uid.to_string(), r#"User::"alice""#);
    }

    #[test]
    fn test_principal_cedar_entity_uid_group() {
        let group = Group::new("admins", None);
        let principal = Principal::Group(group);
        let entity_uid = principal.cedar_entity_uid().unwrap();
        assert_eq!(entity_uid.to_string(), r#"Group::"admins""#);
    }

    #[test]
    fn test_principal_cedar_attr() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        let attrs = principal.cedar_attr().unwrap();
        // Should have empty attributes by default
        assert_eq!(attrs.len(), 0);
    }

    #[test]
    fn test_principal_cedar_ctx() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        let ctx = principal.cedar_ctx().unwrap();
        // Context should be empty by default
        assert!(format!("{:?}", ctx).contains("Context"));
    }

    #[test]
    fn test_principal_serialization() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);

        let serialized = serde_json::to_value(&principal).unwrap();
        let deserialized: Principal = serde_json::from_value(serialized).unwrap();

        assert_eq!(principal.cedar_id(), deserialized.cedar_id());
    }

    #[test]
    fn test_principal_clone() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        let cloned = principal.clone();
        assert_eq!(principal.cedar_id(), cloned.cedar_id());
    }

    #[test]
    fn test_principal_debug() {
        let user = User::new("alice", None, None);
        let principal = Principal::User(user);
        let debug_str = format!("{:?}", principal);
        assert!(debug_str.contains("User"));
    }

    #[test]
    fn test_principal_with_namespace() {
        let user = User::new("alice", None, Some(vec!["App".to_string()]));
        let principal = Principal::User(user);
        assert_eq!(principal.cedar_id(), r#"App::User::"alice""#);
    }
}
