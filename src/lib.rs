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
//! use treetop_core::{Action, AttrValue, PolicyEngine, Request, Decision, User, Principal, Resource, RegexLabeler, LabelRegistryBuilder};
//! use sha2::{Digest, Sha256};
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
//! let label_registry = LabelRegistryBuilder::new()
//!     .add_labeler(Arc::new(RegexLabeler::new(
//!         "Host",
//!         "name",
//!         "nameLabels",
//!         patterns.into_iter().collect(),
//!     )))
//!     .build();
//!
//! let engine = PolicyEngine::new_from_str(&policies).unwrap()
//!     .with_label_registry(label_registry);
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
//! let alice_policies = engine.list_policies_for_user("alice", vec![]).unwrap();
//! // This value is also seralizable to JSON
//! let json = serde_json::to_string(&alice_policies).unwrap();
//!
//! // Check that the policy running is the expected version
//! assert_eq!(engine.current_version().hash, format!("{:x}", Sha256::digest(policies)));
//!
//! ```
//!
//! ## Thread-Safe Sharing
//!
//! For multithreaded applications, wrap `PolicyEngine` in `Arc` to share it across threads:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::thread;
//! # use treetop_core::{PolicyEngine, Request, Principal, User, Action, Resource, Decision};
//! # let engine_base = PolicyEngine::new_from_str("permit(principal,action,resource);").unwrap();
//!
//! let engine = Arc::new(engine_base);
//! let engine_clone = Arc::clone(&engine);
//!
//! let handle = thread::spawn(move || {
//!     // Evaluate policies in a background thread
//!     let request = Request {
//!         principal: Principal::User(User::new("user", None, None)),
//!         action: Action::new("read", None),
//!         resource: Resource::new("Document", "doc1"),
//!     };
//!     let _decision = engine_clone.evaluate(&request);
//! });
//!
//! handle.join().unwrap();
//! ```
//!

pub use build_info::build_info;
pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use labels::{LabelRegistry, LabelRegistryBuilder, Labeler, RegexLabeler};
pub use loader::compile_policy;
pub use types::{
    Action, AttrValue, CedarType, Decision, Group, Groups, PermitPolicies, PermitPolicy,
    PolicyVersion, Principal, Request, Resource, User, UserPolicies,
};

#[cfg(feature = "observability")]
pub use metrics::{EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats, set_sink};

mod build_info;
mod engine;
mod error;
mod labels;
mod loader;
#[cfg(feature = "observability")]
pub mod metrics;
#[cfg(not(feature = "observability"))]
mod metrics;
mod tests;
mod timers;
mod traits;
pub mod types;
