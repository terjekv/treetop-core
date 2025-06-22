# A core library for policies

Use [Cedar](https://docs.cedarpolicy.com) policies to define and enforce access control policies in your application.

## Example

```rust
use treetop_core::{PolicyEngine, Request, Decision, User, Action, Host, initialize_host_patterns};
use regex::Regex;

let policies = r#"
permit (
   principal == User::"alice",
   action == Action::"create_host",
   resource is Host
) when {
    resource.nameLabels.contains("in_domain") &&
    resource.ip.isInRange(ip("10.0.0.0/24")) &&
    resource.name like "*n*"
};
"#;

initialize_host_patterns(vec![
   ("in_domain".to_string(), Regex::new(r"example\.com$").unwrap()),
   ("webserver".to_string(), Regex::new(r"^web-\d+").unwrap())
]);

let engine = PolicyEngine::new_from_str(&policies).unwrap();

let request = Request {
   principal: User::new("alice", None), // User is not in a namespace/scope
   action: Action::new("create_host", None), // Action is not in a namespace/scope
   groups: vec![], // Groups the user belongs to
   resource: Host {
      name: "hostname.example.com".into(),
      ip: "10.0.0.1".parse().unwrap(),
   },
};

let decision = engine.evaluate(&request).unwrap();
assert_eq!(decision, Decision::Allow);
```
