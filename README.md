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

## Observability & Metrics

Treetop includes optional metrics and tracing to help you observe policy evaluation:

- **Feature flag:** Enable `observability` to collect metrics and emit tracing spans.
- **Metrics sink:** Implement `MetricsSink` to capture `EvaluationStats` and `ReloadStats`.
- **Phase timing:** Per-phase durations for labels, entities, groups, and authorize.
- **Prometheus example:** See [examples/prometheus_sink.rs](examples/prometheus_sink.rs).
- **OpenTelemetry example:** See [examples/opentelemetry_tracing.rs](examples/opentelemetry_tracing.rs).
- **Documentation:** See [docs/Metrics.md](docs/Metrics.md).

Enable in your crate:

```toml
[dependencies]
treetop-core = { version = "0", features = ["observability"] }
```

Register a sink:

```rust
use treetop_core::metrics::{set_sink, EvaluationStats, ReloadStats, MetricsSink};

struct MySink;
impl MetricsSink for MySink {
    fn record_evaluation(&self, stats: &EvaluationStats) { println!("{:?}", stats); }
    fn record_reload(&self, stats: &ReloadStats) { println!("{:?}", stats); }
}

set_sink(Some(Box::new(MySink)));
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
 use regex::Regex;
 use std::sync::Arc;
 use treetop_core::{Action, AttrValue, PolicyEngine, Request, Decision, User, Principal, Resource, RegexLabeler, LabelRegistryBuilder};

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

 // Used to create attributes for hosts based on their names.
 let patterns = vec![
     ("in_domain".to_string(), Regex::new(r"example\.com$").unwrap()),
     ("webserver".to_string(), Regex::new(r"^web-\d+").unwrap()),
 ];
 let label_registry = LabelRegistryBuilder::new()
     .add_labeler(Arc::new(RegexLabeler::new(
         "Host",
         "name",
         "nameLabels",
         patterns.into_iter().collect(),
     )))
     .build();

 let engine = PolicyEngine::new_from_str(&policies).unwrap()
     .with_label_registry(label_registry);

 let request = Request {
    principal: Principal::User(User::new("alice", None, None)), // No groups, no namespace
    action: Action::new("create_host", None), // Action is not in a namespace
    resource: Resource::new("Host", "hostname.example.com")
     .with_attr("name", AttrValue::String("hostname.example.com".into()))
     .with_attr("ip", AttrValue::Ip("10.0.0.1".into()))
 };

 let decision = engine.evaluate(&request).unwrap();
 assert!(matches!(decision, Decision::Allow { .. }));

 // Access policy version information
 if let Decision::Allow { version, .. } = &decision {
     println!("Policy hash: {}", version.hash);
     println!("Policy loaded at: {}", version.loaded_at);
 }

 // List all of alice's policies
 let policies = engine.list_policies_for_user("alice", vec![]).unwrap();
 // This value is also seralizable to JSON
 let json = serde_json::to_string(&policies).unwrap();
```

## Groups

Groups are listed as the principal entity type `Group`, and to permit access to member of a group, you can use the `in` operator. If you say `principal in Group::"admins"`, it will match any principal that is a member of the group `admins`, but if you say `principal == Group::"admins"`, it will only match the group itself, not its members. You will almost always want to use the `in` operator when dealing with groups...

```cedar
permit (
   principal in Group::"admins",
   action == Action::"manage_hosts",
   resource is Host
)
```

This is then queried as follows in a request:

```rust
let request = Request {
   principal: Principal::User(User::new("alice", None, None)),
   action: Action::new("manage_hosts", None),
   resource: Resource::new("Host", "hostname.example.com")
    .with_attr("name", AttrValue::String("hostname.example.com".into()))
    .with_attr("ip", AttrValue::Ip("10.0.0.1".into()))
};
```

Note that namespaces for groups are inherited from vector of namespaces passed during creation of the `User` struct. This implies that you cannot use different namespaces for groups and users in the same query.

## Another example

Imagine the following policy:

```cedar
permit (
   principal == User::"alice",
   action == Action::"build_house",
   resource is House
) when {
    resource.id == "house-1"
};
```

This can be queried with the following request:

```rust
Request {
   principal: Principal::User(User::new("alice", None, None)),
   action: Action::new("build_house", None),
   resource: Resource::new("House", "house-1")
};
```
