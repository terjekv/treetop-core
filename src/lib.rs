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
//! ## Batch Evaluation with Snapshots
//!
//! For consistent batch evaluation where you need to guarantee that all requests use the same
//! policy and label state, use `snapshot()` to freeze the engine state, then evaluate multiple
//! requests against that snapshot:
//!
//! ```rust
//! use std::sync::Arc;
//! use std::thread;
//! use treetop_core::{PolicyEngine, Request, Principal, User, Action, Resource, Decision};
//!
//! let policies = r#"
//! permit (
//!    principal == User::"alice",
//!    action == Action::"read",
//!    resource == Document::"doc1"
//! );
//! permit (
//!    principal == User::"bob",
//!    action == Action::"read",
//!    resource == Document::"doc2"
//! );
//! "#;
//!
//! let engine = PolicyEngine::new_from_str(policies).unwrap();
//!
//! // Create a snapshot - freezes both policies and labels
//! let snapshot = engine.snapshot();
//!
//! // Evaluate multiple requests against the same snapshot
//! let requests = vec![
//!     Request {
//!         principal: Principal::User(User::new("alice", None, None)),
//!         action: Action::new("read", None),
//!         resource: Resource::new("Document", "doc1"),
//!     },
//!     Request {
//!         principal: Principal::User(User::new("bob", None, None)),
//!         action: Action::new("read", None),
//!         resource: Resource::new("Document", "doc2"),
//!     },
//! ];
//!
//! for request in requests {
//!     let decision = snapshot.evaluate(&request).unwrap();
//!     assert!(matches!(decision, Decision::Allow { .. }));
//! }
//!
//! // Access snapshot metadata
//! let version = snapshot.version();
//! let policy_count = snapshot.policy_set().policies().count();
//! assert_eq!(policy_count, 2);
//! ```
//!
//! ## Thread-Safe Batch Evaluation with Snapshots
//!
//! For multithreaded applications that need consistent batch evaluation, create a snapshot and
//! share it across threads using `Arc`. Each thread evaluates requests against the same frozen state:
//!
//! ```rust
//! use std::sync::Arc;
//! use std::thread;
//! use treetop_core::{PolicyEngine, Request, Principal, User, Action, Resource, Decision};
//!
//! let policies = r#"
//! permit (
//!    principal == User::"alice",
//!    action in [Action::"read", Action::"write"],
//!    resource == Document::"doc1"
//! );
//! "#;
//!
//! let engine = PolicyEngine::new_from_str(policies).unwrap();
//!
//! // Create a snapshot and wrap in Arc for sharing across threads
//! let snapshot = Arc::new(engine.snapshot());
//!
//! let mut handles = vec![];
//!
//! // Spawn multiple threads, each evaluating requests against the same snapshot
//! for thread_id in 0..3 {
//!     let snapshot_clone = Arc::clone(&snapshot);
//!
//!     let handle = thread::spawn(move || {
//!         let request = Request {
//!             principal: Principal::User(User::new("alice", None, None)),
//!             action: Action::new(if thread_id == 0 { "read" } else { "write" }, None),
//!             resource: Resource::new("Document", "doc1"),
//!         };
//!
//!         // All threads evaluate against the exact same snapshot state
//!         let decision = snapshot_clone.evaluate(&request).unwrap();
//!         assert!(matches!(decision, Decision::Allow { .. }));
//!     });
//!
//!     handles.push(handle);
//! }
//!
//! for handle in handles {
//!     handle.join().unwrap();
//! }
//! ```
//!

pub use build_info::build_info;
pub use engine::{EngineSnapshot, PolicyEngine};
pub use error::PolicyError;
pub use labels::{LabelRegistry, LabelRegistryBuilder, Labeler, RegexLabeler};
pub use loader::compile_policy;
pub use types::{
    Action, AttrValue, CedarType, Decision, Group, Groups, PermitPolicy, PolicyVersion, Principal,
    Request, Resource, User, UserPolicies,
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
mod traits;
pub mod types;
