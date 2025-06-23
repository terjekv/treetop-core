# A core library for policies

Use [Cedar](https://docs.cedarpolicy.com) policies to define and enforce access control policies in your application.

## Policy examples

Allow a user to create a host if the host's name matches a specific pattern, the host's IP is within a certain range, and the host has a specific label:

```cedar
permit (
   principal == User::"alice",
   action == Action::"create_host",
   resource is Host
) when {
    resource.nameLabels.contains("in_domain") &&
    resource.ip.isInRange(ip("10.0.0.0/24")) &&
    resource.name like "*n*"
};
```

A different users have different permissions when it comes to creating hosts. Alice can create hosts within the domain `example_domain`,
irrespective of the IP range, and with any name. Bob on the other hand can only create hosts with a acceptable names for web servers and
within a specific IP range, and within the same domain.

```cedar
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.nameLabels.contains("example_domain")
};

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
) when {
    resource.ip.isInRange(ip("10.0.1.0/24")) &&
    resource.nameLabels.contains("valid_web_name") &&
    resource.nameLabels.contains("example_domain")
};
```

Alice can perform an action called `assign_to_restricted_ips`, no matter the resource. Bob can only perform the action `assign_to_gateways` for hosts
within the RFC 1918 range for 10.0.0.0/8. The implementation of these action is up to the client application, but we can imagine that restricted IPs
consist of IPs that are critical for infastructure, like gateways, broadcast adresses, and possibly some reserved IPs.

```cedar
permit (
   principal == User::"alice",
   action == Action::"assign_to_restricted_ips",
   resource
);

permit (
   principal == User::"bob",
   action == Action::"assign_to_gateways",
   resource is Host
) when {
    resource.ip.isInRange(ip("10.0.0.0/8"))
};
```

## Code example

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
