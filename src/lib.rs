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
//! use treetop_core::{PolicyEngine, Request, Decision, User, Action, Host, initialize_host_patterns};
//! use regex::Regex;
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
//! initialize_host_patterns(vec![
//!    ("in_domain".to_string(), Regex::new(r"example\.com$").unwrap()),
//!    ("webserver".to_string(), Regex::new(r"^web-\d+").unwrap())
//! ]);
//!
//! let engine = PolicyEngine::new_from_str(&policies).unwrap();
//!
//! let request = Request {
//!    principal: User::new("alice", None), // User is not in a namespace/scope
//!    action: Action::new("create_host", None), // Action is not in a namespace/scope
//!    groups: vec![], // Groups the user belongs to
//!    resource: Host {
//!       name: "hostname.example.com".into(),
//!       ip: "10.0.0.1".parse().unwrap(),
//!    },
//! };
//!
//! let decision = engine.evaluate(&request).unwrap();
//! assert_eq!(decision, Decision::Allow);
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

pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use host_patterns::initialize_host_patterns;
pub use models::{Action, Decision, Group, Request, Resource, Resource::Host, User, UserPolicies};

mod engine;
mod error;
mod host_patterns;
mod loader;
mod models;
mod traits;
