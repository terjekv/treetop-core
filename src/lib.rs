//! Usage example:
//!
//! Here we declare a policy that allows "alice" to create a host if and only if the following conditions are met:
//! - The host's nameLabel set contains "example_domain". This is created via regular expressions on the name from
//!   the `initialize_host_patterns` function.
//! - The host's IP address is within the network "10.0.0.0/24".
//! - The host's name contains the letter 'n'
//!
//! Note that we do not require the host to have the nameLabel "webserver" for "alice" to create it.
//!
//! ```rust
//! use regex::Regex;
//! use std::sync::Arc;
//! use treetop_core::{Action, AttrValue, PolicyEngine, Request, Decision, User, Principal, Resource, RegexLabeler, LABEL_REGISTRY};
//!
//! let policies = r#"
//! permit (
//!    principal == User::"alice",
//!    action == Action::"create_host",
//!    resource is Host
//! ) when {
//!     resource.nameLabels.contains("in_domain") &&
//!     resource.ip.isInRange(ip("10.0.0.0/24")) &&
//!     resource.name like "*n*"
//! };
//! "#;
//!
//! // Used to create attributes for hosts based on their names.
//! let patterns = vec![
//!     ("in_domain".to_string(), Regex::new(r"example\.com$").unwrap()),
//!     ("webserver".to_string(), Regex::new(r"^web-\d+").unwrap()),
//! ];
//! LABEL_REGISTRY.load(vec![Arc::new(RegexLabeler::new(
//!     "Host",
//!     "name",
//!     "nameLabels",
//!     patterns.into_iter().collect(),
//! ))]);
//!
//! let engine = PolicyEngine::new_from_str(&policies).unwrap();
//!
//! let request = Request {
//!    principal: Principal::User(User::new("alice", None, None)), // No groups, no namespace
//!    action: Action::new("create_host", None), // Action is not in a namespace
//!    resource: Resource::new("Host", "hostname.example.com")
//!     .with_attr("name", AttrValue::String("hostname.example.com".into()))
//!     .with_attr("ip", AttrValue::Ip("10.0.0.1".into()))
//! };
//!
//! let decision = engine.evaluate(&request).unwrap();
//! assert!(matches!(decision, Decision::Allow { .. }));
//!
//! // List all of alice's policies
//! let policies = engine.list_policies_for_user("alice", vec![]).unwrap();
//! // This value is also seralizable to JSON
//! let json = serde_json::to_string(&policies).unwrap();
//! ```
//!
//!
//!
//!

pub use build_info::build_info;
pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use labels::{LABEL_REGISTRY, Labeler, RegexLabeler};
pub use models::{
    Action, AttrValue, Decision, Group, Groups, Principal, Request, Resource, User, UserPolicies,
};

mod build_info;
mod engine;
mod error;
mod labels;
mod loader;
mod models;
mod tests;
mod traits;
