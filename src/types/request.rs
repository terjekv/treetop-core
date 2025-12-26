//! Authorization request type.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::action::Action;
use super::principal::Principal;
use super::resource::Resource;

/// The API-level request, with strongly-typed principal, action, groups, resource, and context.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Request {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CedarAtom;
    use crate::types::{Action, Group, User};
    use insta::assert_json_snapshot;

    #[test]
    fn assert_request_serialization() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("create", None),
            resource: Resource::new("Host", "web-01"),
        };
        let serialized = serde_json::to_value(&request).unwrap();

        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(serialized);
        });
    }

    #[test]
    fn test_request_with_group_principal() {
        let request = Request {
            principal: Principal::Group(Group::new("admins", None)),
            action: Action::new("delete", None),
            resource: Resource::new("Database", "prod"),
        };
        
        let serialized = serde_json::to_value(&request).unwrap();
        assert!(serialized["principal"].to_string().contains("admins"));
    }

    #[test]
    fn test_request_with_namespaced_types() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, Some(vec!["App".to_string()]))),
            action: Action::new("create", Some(vec!["Admin".to_string()])),
            resource: Resource::new("Host", "web-01"),
        };
        
        let serialized = serde_json::to_value(&request).unwrap();
        let deserialized: Request = serde_json::from_value(serialized).unwrap();
        assert_eq!(request.principal.cedar_id(), deserialized.principal.cedar_id());
    }

    #[test]
    fn test_request_with_resource_attributes() {
        use crate::types::AttrValue;
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "doc1")
                .with_attr("owner", AttrValue::String("alice".to_string()))
                .with_attr("public", AttrValue::Bool(false)),
        };
        
        assert_eq!(request.resource.id(), "doc1");
    }

    #[test]
    fn test_request_clone() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("File", "file1"),
        };
        
        let cloned = request.clone();
        assert_eq!(request.principal.cedar_id(), cloned.principal.cedar_id());
        assert_eq!(request.action.cedar_id(), cloned.action.cedar_id());
        assert_eq!(request.resource.id(), cloned.resource.id());
    }

    #[test]
    fn test_request_debug() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("File", "file1"),
        };
        
        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("Request"));
    }
}
