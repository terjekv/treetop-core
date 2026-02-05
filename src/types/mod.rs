//! Data model types for requests and Cedar entity conversion.
//!
//! Canonical string forms:
//! - User: `User::"alice"` or `NS::User::"alice"` with optional groups `[admins,devs]`
//! - Group: `Group::"admins"` or `NS::Group::"admins"`
//! - Action: `Action::"create"` or `NS::Action::"create"`
//! - Resource: `Kind::"id"` or `NS::Kind::"id"`
//!
//! Quoting rules: identity elements may be quoted; parsing accepts both
//! quoted and unquoted forms where unambiguous.

mod action;
mod attr_value;
mod cedar_type;
mod decision;
mod entity_uid;
mod group;
mod principal;
mod qualified_id;
mod request;
mod resource;
mod user;
mod user_policies;

// Re-export everything for backward compatibility
pub use action::Action;
pub use attr_value::AttrValue;
pub use cedar_type::CedarType;
pub use decision::{Decision, FromDecisionWithPolicy, PermitPolicies, PermitPolicy, PolicyVersion};
pub use entity_uid::{
    action_entity_uid, group_entity_uid, namespace_segments, resource_entity_uid, user_entity_uid,
};
pub use group::{Group, Groups};
pub use principal::Principal;
pub use qualified_id::{
    ActionId, ActionMarker, GroupId, GroupMarker, QualifiedId, UserId, UserMarker,
};
pub use request::Request;
pub use resource::Resource;
pub use user::User;
pub use user_policies::{PolicyEffectFilter, PolicyMatch, PolicyMatchReason, UserPolicies};
