use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use itertools::Itertools;

use cedar_policy::{ActionConstraint, Context, EntityUid, Policy, RestrictedExpression};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::error::PolicyError;
use crate::host_patterns::HOST_PATTERNS;
use crate::traits::CedarAtom;

/// The API-level request, with strongly-typed principal, action, groups, and resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub principal: User,
    pub action: Action,
    pub groups: Groups,
    pub resource: Resource,
}

/// Allow or deny decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Decision {
    Allow,
    Deny,
}

impl From<cedar_policy::Decision> for Decision {
    fn from(decision: cedar_policy::Decision) -> Self {
        match decision {
            cedar_policy::Decision::Allow => Decision::Allow,
            cedar_policy::Decision::Deny => Decision::Deny,
        }
    }
}

/// A resource in our domain: either a Photo or a Host record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resource {
    Photo { id: String },
    Host { name: String, ip: IpAddr },
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resource::Photo { id } => write!(f, "Photo::\"{}\"", id),
            Resource::Host { name, .. } => write!(f, "Host::\"{}\"", name),
        }
    }
}

impl CedarAtom for Resource {
    fn cedar_entity_uid(&self) -> Result<cedar_policy::EntityUid, PolicyError> {
        let literal = match self {
            Resource::Photo { id } => {
                format!(r#"Photo::"{id}""#)
            }
            Resource::Host { name, .. } => {
                format!(r#"Host::"{name}""#)
            }
        };
        cedar_policy::EntityUid::from_str(&literal)
            .map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        let mut attrs = std::collections::HashMap::new();
        match self {
            Resource::Photo { id } => {
                attrs.insert(
                    "id".to_string(),
                    RestrictedExpression::new_string(id.clone()),
                );
            }
            Resource::Host { name, ip } => {
                attrs.insert(
                    "name".to_string(),
                    RestrictedExpression::new_string(name.clone()),
                );
                attrs.insert(
                    "ip".to_string(),
                    RestrictedExpression::new_ip(ip.to_string()),
                );

                let reg = HOST_PATTERNS.read().unwrap();
                let mut matched = Vec::new();
                for (label, re) in reg.iter() {
                    if re.is_match(name) {
                        matched.push(RestrictedExpression::new_string(label.clone()));
                    }
                }
                attrs.insert(
                    "nameLabels".to_string(),
                    RestrictedExpression::new_set(matched),
                );
            }
        }
        Ok(attrs)
    }

    fn cedar_ctx(&self) -> Result<Context, PolicyError> {
        match self {
            Resource::Host { name, ip } => {
                let result = Context::from_pairs(vec![
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string(name.clone()),
                    ),
                    (
                        "ip".to_string(),
                        RestrictedExpression::new_ip(ip.to_string()),
                    ),
                ])?;
                Ok(result)
            }
            Resource::Photo { .. } => Ok(Context::empty()),
        }
    }

    fn cedar_type() -> &'static str {
        "Resource"
    }

    fn cedar_id(&self) -> &str {
        match self {
            Resource::Photo { id } => id,
            Resource::Host { name, .. } => name,
        }
    }
}

/// A user principal, possibly scoped (e.g. User::Application::"alice").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub scope: Option<String>,
    pub id: String,
}

impl std::fmt::Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(scope) = &self.scope {
            write!(f, "User::{}::\"{}\"", scope, self.id)
        } else {
            write!(f, "User::\"{}\"", self.id)
        }
    }
}

impl User {
    /// Create a new user with an optional scope.
    pub fn new<T: Into<String>>(id: T, scope: Option<Vec<String>>) -> Self {
        User {
            scope: scope.map(|s| s.join("::")),
            id: id.into(),
        }
    }

    /// Create a new user without a scope.
    pub fn without_scope<T: Into<String>>(id: T) -> Self {
        User::new(id, None)
    }
}

impl CedarAtom for User {
    fn cedar_type() -> &'static str {
        "User"
    }

    fn cedar_id(&self) -> &str {
        &self.id
    }
}

impl<T> From<T> for User
where
    T: Into<String>,
{
    fn from(v: T) -> Self {
        User {
            scope: None,
            id: v.into(),
        }
    }
}

/// An action, possibly scoped (e.g. Action::Infra::"delete_vm").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub scope: Option<String>,
    pub id: String,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(scope) = &self.scope {
            write!(f, "Action::{}::\"{}\"", scope, self.id)
        } else {
            write!(f, "Action::\"{}\"", self.id)
        }
    }
}

impl Action {
    /// Create a new action with an optional scope.
    pub fn new<T: Into<String>>(id: T, scope: Option<Vec<String>>) -> Self {
        Action {
            scope: scope.map(|s| s.join("::")),
            id: id.into(),
        }
    }

    /// Create a new action without a scope.
    pub fn without_scope<T: Into<String>>(id: T) -> Self {
        Action::new(id, None)
    }
}

impl CedarAtom for Action {
    fn cedar_type() -> &'static str {
        "Action"
    }

    fn cedar_id(&self) -> &str {
        &self.id
    }
}

impl<T> From<T> for Action
where
    T: Into<String>,
{
    fn from(v: T) -> Self {
        Action {
            scope: None,
            id: v.into(),
        }
    }
}

/// A group identifier (e.g. Group::"devs").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group(pub String);

impl CedarAtom for Group {
    fn cedar_type() -> &'static str {
        "Group"
    }

    fn cedar_id(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groups(pub Vec<Group>);

impl std::fmt::Display for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let group_names: Vec<String> = self.0.iter().map(|g| g.0.clone()).collect();
        write!(f, "[{}]", group_names.join(", "))
    }
}

/// A set of permissions for a given user.
#[derive(Debug, Clone)]
pub struct UserPolicies {
    user: String,
    policies: Vec<Policy>,
    actions: Vec<EntityUid>,
}
impl UserPolicies {
    pub fn new(user: &str, policies: &[Policy]) -> Self {
        let actions: Vec<EntityUid> = policies
            .iter()
            .flat_map(|p| match p.action_constraint() {
                // exactly one action
                ActionConstraint::Eq(act) => vec![act.clone()],
                // multiple actions
                ActionConstraint::In(acts) => acts.clone(),
                // “any” means unconstrained — skip or handle however you like
                ActionConstraint::Any => Vec::new(),
            })
            .collect();

        UserPolicies {
            user: user.to_string(),
            policies: policies.to_vec(),
            actions,
        }
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    pub fn actions(&self) -> Vec<EntityUid> {
        self.actions.clone()
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Get the actions as a sorted list of strings.
    pub fn actions_by_name(&self) -> Vec<String> {
        self.actions
            .iter()
            .map(|a| a.to_string())
            .sorted()
            .collect()
    }

    /// Get the policies as a sorted list of strings.
    pub fn policies_by_name(&self) -> Vec<String> {
        self.policies
            .iter()
            .map(|p| p.to_string())
            .sorted()
            .collect()
    }
}

impl Serialize for UserPolicies {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policies = self.policies();

        let mut policies_as_json: Vec<Value> = Vec::new();

        for policy in policies {
            let json = match policy.to_json() {
                Ok(json) => json,
                Err(e) => return Err(serde::ser::Error::custom(e)),
            };
            policies_as_json.push(json);
        }

        let mut s = ser.serialize_struct("UserPolicies", 2)?;
        s.serialize_field("user", &self.user)?;
        s.serialize_field("policies", &policies_as_json)?;
        s.end()
    }
}
