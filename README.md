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
use treetop_core::{PolicyEngine, Request, Decision, User, Action, initialize_host_patterns};
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
   principal: User::new_from_username("alice"), // User without groups, no namespace/scope
   action: Action::new("create_host", None), // Action is not in a namespace/scope
   resource: Resource::Host {
      name: "hostname.example.com".into(),
      ip: "10.0.0.1".parse().unwrap(),
   },
};

let decision = engine.evaluate(&request).unwrap();
assert_eq!(decision, Decision::Allow);

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
   principal: User::new_from_username("alice"),
   action: Action::new("manage_hosts", None),
   resource: Resource::Host {
      name: "hostname.example.com".into(),
      ip: "10.0.0.1".parse().unwrap(),
   },
};
```

Note that scopes for groups have to be explicity stated in the group parameter, ala `Group::Myapp::"admins"`, as opposed to users and actions, where the scope is passed as a vector of strings during the creation of the `User` and `Action` structs.

## Passing generic resources

It is impractical to hard code all relevant resource types into the policy engine. Instead, there is the option to pass a `Generic` resource into the engine, which takes two parameters, a `kind` and an `id`. This allows for more flexibility in defining resources without needing to explicitly enumerate all possible types.

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
   principal: User::new_from_username("alice"),
   action: Action::new("build_house", None),
   resource: Resource::Generic {
      kind: "House".into(),
      id: "house-1".into(),
   },
};
```

This allows for a querying resources that are not explicitly defined in the policy engine, but instead defined in the policy file.
Both `id` and `kind` are passed as context, as strings, into the query. `kind` will always match the resource name.
