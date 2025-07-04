use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;
use std::net::IpAddr;
use std::str::FromStr;

use itertools::Itertools;
use strum_macros::{Display, EnumDiscriminants, EnumString};

use cedar_policy::{ActionConstraint, Context, EntityUid, Policy, RestrictedExpression};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::error::PolicyError;
use crate::host_name_labels::HOST_PATTERNS;
use crate::traits::CedarAtom;

use utoipa::ToSchema;

/// A principal for a policy query.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum Principal {
    User(User),
    Group(Group),
}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Principal::User(user) => write!(f, "{user}"),
            Principal::Group(group) => write!(f, "{group}"),
        }
    }
}

struct CedarParts<'a> {
    id: &'a str,
    type_part: Option<String>,
    namespace: Option<Vec<String>>,
}

/// Dispatch the CedarAtom trait to the correct type.
impl CedarAtom for Principal {
    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        match self {
            Principal::User(user) => user.cedar_entity_uid(),
            Principal::Group(group) => group.cedar_entity_uid(),
        }
    }
    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        match self {
            Principal::User(user) => user.cedar_attr(),
            Principal::Group(group) => group.cedar_attr(),
        }
    }
    fn cedar_ctx(&self) -> Result<Context, PolicyError> {
        match self {
            Principal::User(user) => user.cedar_ctx(),
            Principal::Group(group) => group.cedar_ctx(),
        }
    }
    fn cedar_type() -> &'static str {
        "Principal"
    }
    fn cedar_id(&self) -> String {
        match self {
            Principal::User(user) => user.cedar_id(),
            Principal::Group(group) => group.cedar_id(),
        }
    }
}

/// The API-level request, with strongly-typed principal, action, groups, and resource.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Request {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
}

/// A permit policy that permitted a specific action on a resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default, ToSchema)]
pub struct PermitPolicy {
    pub literal: String,
    pub json: Value,
}

/// Allow or deny decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub enum Decision {
    Allow { policy: PermitPolicy },
    Deny,
}

impl Display for Decision {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Decision::Allow { policy } => write!(f, "Allow({})", policy.literal),
            Decision::Deny => write!(f, "Deny"),
        }
    }
}

pub trait FromDecisionWithPolicy {
    fn from_decision_with_policy(response: cedar_policy::Decision, policy: PermitPolicy) -> Self;
}

impl FromDecisionWithPolicy for Decision {
    fn from_decision_with_policy(decision: cedar_policy::Decision, policy: PermitPolicy) -> Self {
        match decision {
            cedar_policy::Decision::Allow => Decision::Allow { policy },
            cedar_policy::Decision::Deny => Decision::Deny,
        }
    }
}

/// A resource in our domain.
#[derive(Debug, Clone, Serialize, Deserialize, EnumDiscriminants, ToSchema)]
#[strum_discriminants(name(ResourceKind), derive(EnumString, Display))]
#[strum(serialize_all = "PascalCase")]
pub enum Resource {
    Photo {
        id: String,
    },
    Host {
        name: String,
        #[schema(value_type = String)]
        ip: IpAddr,
    },
    Generic {
        kind: String,
        id: String,
    },
}

impl Display for Resource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Turn &self into its discriminant:
        let kind = ResourceKind::from(self).to_string();
        // Pick the right “id” field for each variant:
        let id = match self {
            Resource::Photo { id } => id,
            Resource::Host { name, .. } => name,
            Resource::Generic { id, .. } => id,
        };
        write!(f, "{kind}::\"{id}\"")
    }
}

impl CedarAtom for Resource {
    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        let literal = match self {
            Resource::Generic { kind, id } => {
                format!("{kind}::\"{id}\"")
            }
            _ => {
                let kind = ResourceKind::from(self).to_string();
                let id = self.cedar_id();
                format!("{kind}::\"{id}\"")
            }
        };

        EntityUid::from_str(&literal).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        let mut attrs = HashMap::new();
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
            Resource::Generic { kind, id } => {
                attrs.insert(
                    "kind".into(),
                    RestrictedExpression::new_string(kind.clone()),
                );
                attrs.insert("id".into(), RestrictedExpression::new_string(id.clone()));
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
            Resource::Generic { kind, id } => {
                let result = Context::from_pairs(vec![
                    (
                        "kind".into(),
                        RestrictedExpression::new_string(kind.clone()),
                    ),
                    ("id".into(), RestrictedExpression::new_string(id.clone())),
                ])?;
                Ok(result)
            }
        }
    }

    fn cedar_type() -> &'static str {
        "Resource"
    }

    fn cedar_id(&self) -> String {
        match self {
            Resource::Photo { id } => id.clone(),
            Resource::Host { name, .. } => name.clone(),
            Resource::Generic { id, .. } => id.clone(),
        }
    }
}

/// Marker type for Users
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum UserMarker {}
/// Marker type for Group
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum GroupMarker {}
/// Marker type for Actions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum ActionMarker {}

/// A fully‐qualified identifier, with zero runtime cost over `(Vec<String>, String)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct QualifiedId<T> {
    id: String,
    namespace: Vec<String>,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> QualifiedId<T> {
    /// Construct from its parts.  Guaranteed valid by signature.
    pub fn new(id: impl Into<String>, namespace: Option<Vec<String>>) -> Self {
        QualifiedId {
            id: id.into(),
            namespace: namespace.unwrap_or_default(),
            _marker: PhantomData,
        }
    }

    /// Get the raw id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the namespace path.
    #[allow(dead_code)]
    pub fn namespace(&self) -> &[String] {
        &self.namespace
    }

    /// Render as `"Ns1::Ns2::Type::"id""`.
    pub fn fmt_qualified(&self, ty: &str) -> String {
        let mut parts = self.namespace.join("::");
        if !parts.is_empty() {
            parts.push_str("::");
        }
        format!(
            r#"{parts}{ty}::"{id}""#,
            id = self.id,
            parts = parts,
            ty = ty
        )
    }
}

impl<T> Display for QualifiedId<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // We don't know `T`'s name here; we'll implement Display on the wrappers.
        write!(f, "{}", self.id)
    }
}

/// A User’s fully‐qualified ID.
pub type UserId = QualifiedId<UserMarker>;
/// A Group’s fully‐qualified ID.
pub type GroupId = QualifiedId<GroupMarker>;
/// An Action’s fully‐qualified ID.
pub type ActionId = QualifiedId<ActionMarker>;

/// A user principal, possibly with a namespace (e.g. Application::User::"alice").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    id: UserId,
    groups: Groups,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.id.fmt_qualified(Self::cedar_type()))
    }
}

impl User {
    /// Create a new user with optional groups and an optional namespace
    ///
    /// This constructor allows you to create a user with a specific ID, and optionally
    /// assign them to one or more groups, as well as specify a namespace for the user.
    ///
    /// The groups will be placed in the same namespace as the user.
    ///
    /// ## Parameters
    ///
    /// - `id`: The unique identifier for the user.
    /// - `groups`: An optional list of groups to which the user belongs.
    /// - `namespace`: An optional namespace for the user and the groups.
    ///
    /// ## Returns
    ///
    /// A new `User` instance.
    pub fn new<T: Into<String>>(
        id: T,
        groups: Option<Vec<String>>,
        namespace: Option<Vec<String>>,
    ) -> Self {
        User {
            id: UserId::new(id, namespace.clone()),
            groups: Groups::new(groups.unwrap_or_default(), namespace),
        }
    }

    pub fn groups(&self) -> &Groups {
        &self.groups
    }
}

impl CedarAtom for User {
    fn cedar_type() -> &'static str {
        "User"
    }

    fn cedar_id(&self) -> String {
        self.id.fmt_qualified(Self::cedar_type())
    }
}

impl FromStr for User {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (user_part, groups_part) = if let Some(idx) = s.find('[') {
            let (left, right) = s.split_at(idx);
            (left.trim(), Some(right.trim()))
        } else {
            (s.trim(), None)
        };

        let parts = split_string_into_cedar_parts(user_part)?;

        // If there are groups, parse them
        let groups = if let Some(groups_str) = groups_part {
            let groups_str = groups_str.trim_matches(|c| c == '[' || c == ']');
            let groups: Vec<String> = groups_str
                .split(',')
                .map(|g| g.trim().to_string())
                .collect();
            Some(groups)
        } else {
            None
        };

        let expected = Self::cedar_type();
        #[allow(clippy::collapsible_if)] // https://github.com/rust-lang/rust/issues/53667
        if let Some(type_part) = parts.type_part {
            if type_part != expected {
                return Err(PolicyError::InvalidFormat(format!(
                    "Expected type `{expected}`, found `{type_part}` in `{s}`"
                )));
            }
        }

        Ok(User::new(parts.id, groups, parts.namespace))
    }
}

/// An action, possibly with a namespace (e.g. Infra::Action::"delete_vm").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Action {
    id: ActionId,
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.id.fmt_qualified(Self::cedar_type()))
    }
}

impl Action {
    /// Create a new action with an optional namespace.
    pub fn new<T: Into<String>>(id: T, namespace: Option<Vec<String>>) -> Self {
        Action {
            id: ActionId::new(id, namespace),
        }
    }

    /// Create a new action without a namespace.
    pub fn without_namespace<T: Into<String>>(id: T) -> Self {
        Action::new(id, None)
    }
}

impl CedarAtom for Action {
    fn cedar_type() -> &'static str {
        "Action"
    }

    fn cedar_id(&self) -> String {
        self.id.fmt_qualified(Self::cedar_type())
    }
}

impl FromStr for Action {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = split_string_into_cedar_parts(s)?;

        let expected = Self::cedar_type();
        #[allow(clippy::collapsible_if)] // https://github.com/rust-lang/rust/issues/53667
        if let Some(type_part) = parts.type_part {
            if type_part != expected {
                return Err(PolicyError::InvalidFormat(format!(
                    "Expected type `{expected}`, found `{type_part}` in `{s}`"
                )));
            }
        }

        Ok(Action::new(parts.id, parts.namespace))
    }
}

impl<T> From<T> for Action
where
    T: Into<String>,
{
    fn from(v: T) -> Self {
        let v = v.into();
        Action::from_str(&v).unwrap_or_else(|_| Action::new(v, None))
    }
}

/// A group identifier (e.g. Group::"devs").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Group(GroupId);

impl Group {
    /// Create a new group with an optional namespace.
    pub fn new<S: AsRef<str>>(name: S, namespace: Option<Vec<String>>) -> Self {
        Group(GroupId::new(name.as_ref(), namespace))
    }
}

impl Display for Group {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0.fmt_qualified(Self::cedar_type()))
    }
}

impl CedarAtom for Group {
    fn cedar_type() -> &'static str {
        "Group"
    }

    fn cedar_id(&self) -> String {
        self.0.fmt_qualified(Self::cedar_type())
    }
}

impl FromStr for Group {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = split_string_into_cedar_parts(s)?;

        let expected = Self::cedar_type();
        #[allow(clippy::collapsible_if)] // https://github.com/rust-lang/rust/issues/53667
        if let Some(type_part) = parts.type_part {
            if type_part != expected {
                return Err(PolicyError::InvalidFormat(format!(
                    "Expected type `{expected}`, found `{type_part}` in `{s}`"
                )));
            }
        }

        Ok(Group::new(parts.id, parts.namespace))
    }
}

/// A collection of Group entries.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct Groups(Vec<Group>);

impl Groups {
    pub fn new<I, S>(groups: I, namespace: Option<Vec<String>>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let v = groups
            .into_iter()
            .map(|g| Group::new(g.as_ref(), namespace.clone()))
            .collect();
        Groups(v)
    }

    /// Check if the Groups collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the number of groups in this collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Display for Groups {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let group_names: Vec<String> = self
            .0
            .iter()
            .map(|g| g.0.clone().id().to_string())
            .collect();
        write!(f, "[{}]", group_names.join(", "))
    }
}

impl Iterator for Groups {
    type Item = Group;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop()
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

fn split_string_into_cedar_parts(s: &str) -> Result<CedarParts<'_>, PolicyError> {
    let parts: Vec<&str> = s.split("::").collect();
    if parts.len() == 1 {
        return Ok(CedarParts {
            id: parts[0],
            type_part: None,
            namespace: None,
        });
    }

    // last segment should be `"id"`, it may be quoted, if so, strip the quotes
    let id = parts.last().unwrap().trim_matches('"');
    let type_part = parts[parts.len() - 2];

    // everything before that is the namespace
    let namespace = parts[..parts.len() - 2]
        .iter()
        .map(|s| s.to_string())
        .collect();

    Ok(CedarParts {
        id,
        type_part: Some(type_part.to_string()),
        namespace: Some(namespace),
    })
}

#[cfg(test)]
mod tests {
    use yare::parameterized;

    use super::*;

    fn quote_last_element(s: &str) -> String {
        let target = if s.contains("::") {
            let parts: Vec<&str> = s.split("::").collect();
            let last_part = parts.last().unwrap().trim_matches('"');
            format!("{}::\"{}\"", parts[..parts.len() - 1].join("::"), last_part)
        } else {
            s.to_string()
        };
        target
    }

    #[parameterized(
        alice_unquoted_without_namespace = {
            "User::alice", CedarParts { id: "alice", type_part: Some("User".to_string()), namespace: Some(vec![]) } },
        alice_unquoted_with_namespace = {
            "Infra::User::alice", CedarParts { id: "alice", type_part: Some("User".to_string()), namespace: Some(vec!["Infra".to_string()]) } },
        alice_unquoted_with_multiple_namespaces = {
            "Infra::Core::User::alice", CedarParts { id: "alice", type_part: Some("User".to_string()), namespace: Some(vec!["Infra".to_string(), "Core".to_string()]) } },
        alice_quoted = {
            "User::\"alice\"", CedarParts { id: "alice", type_part: Some("User".to_string()), namespace: Some(vec![]) } },
        alice_quoted_with_namespace = {
            "Infra::User::\"alice\"", CedarParts { id: "alice", type_part: Some("User".to_string()), namespace: Some(vec!["Infra".to_string()]) } },
        alice_quoted_with_multiple_namespaces = {
            "Infra::Core::User::\"alice\"", CedarParts { id: "alice", type_part: Some("User".to_string()), namespace: Some(vec!["Infra".to_string(), "Core".to_string()]) } },

    )]

    fn test_split_string_into_cedar_parts(str: &str, expected: CedarParts) {
        let result = split_string_into_cedar_parts(str).unwrap();
        assert_eq!(result.id, expected.id);
        assert_eq!(result.type_part, expected.type_part);
        assert_eq!(result.namespace, expected.namespace);
    }

    #[parameterized(
        alice = { "User::alice", "alice", None, None },
        alice_with_groups = { "User::alice[admins,users]", "alice", Some(vec!["admins".to_string(), "users".to_string()]), None },
        alice_with_namespace = { "Infra::User::alice", "alice", None, Some(vec!["Infra".to_string()]) },
        alice_with_multiple_namespaces = { "Infra::Core::User::alice", "alice", None, Some(vec!["Infra".to_string(), "Core".to_string()]) },
        alice_with_groups_and_namespace = { "Infra::User::alice[admins,users]", "alice", Some(vec!["admins".to_string(), "users".to_string()]), Some(vec!["Infra".to_string()]) },
    )]
    fn test_user_from_str(
        user_str: &str,
        expected_id: &str,
        expected_groups: Option<Vec<String>>,
        expected_namespace: Option<Vec<String>>,
    ) {
        let user = User::from_str(user_str).unwrap();

        let target = if user_str.contains("[") {
            // Drop everything after the first `[` to remove groups
            user_str.split('[').next().unwrap().trim()
        } else {
            user_str.trim()
        };

        assert_eq!(user.id.fmt_qualified("User"), quote_last_element(target));

        assert_eq!(user.id.id(), expected_id);
        assert_eq!(
            user.groups
                .0
                .iter()
                .map(|g| g.0.id().to_string())
                .collect::<Vec<_>>(),
            expected_groups.unwrap_or_default()
        );
        assert_eq!(
            user.id.namespace(),
            expected_namespace.as_deref().unwrap_or(&vec![])
        );
    }

    #[parameterized(
        action_unquoted_without_namespace = { "Action::create_host", "create_host" },
        action_unquoted_with_namespace = { "Infra::Action::create_host", "create_host" },
        action_unquoted_with_multiple_namespaces = { "Infra::Core::Action::create_host", "create_host" },
        action_quoted = { "Action::\"create_host\"", "create_host" },
        action_quoted_with_namespace = { "Infra::Action::\"create_host\"", "create_host" },
        action_quoted_with_multiple_namespaces = { "Infra::Core::Action::\"create_host\"", "create_host" },
    )]
    fn test_action_from_str(action_str: &str, expected_id: &str) {
        let action = Action::from_str(action_str).unwrap();
        assert_eq!(action.id.id(), expected_id);
        assert_eq!(
            action.id.fmt_qualified("Action"),
            quote_last_element(action_str)
        );
    }

    #[parameterized(
        group_unquoted_without_namespace = { "Group::admins", "admins", None },
        group_unquoted_with_namespace = { "Infra::Group::admins", "admins", Some(vec!["Infra".to_string()]) },
        group_unquoted_with_multiple_namespaces = { "Infra::Core::Group::admins", "admins", Some(vec!["Infra".to_string(), "Core".to_string()]) },
        group_quoted = { "Group::\"admins\"", "admins", None },
        group_quoted_with_namespace = { "Infra::Group::\"admins\"", "admins", Some(vec!["Infra".to_string()]) },
        group_quoted_with_multiple_namespaces = { "Infra::Core::Group::\"admins\"", "admins", Some(vec!["Infra".to_string(), "Core".to_string()]) },
    )]
    fn test_group_from_str(
        group_str: &str,
        expected_id: &str,
        expected_namespace: Option<Vec<String>>,
    ) {
        let group = Group::from_str(group_str).unwrap();
        assert_eq!(group.0.id(), expected_id);
        assert_eq!(
            group.0.fmt_qualified("Group"),
            quote_last_element(group_str)
        );
        assert_eq!(
            group.0.namespace(),
            expected_namespace.as_deref().unwrap_or(&vec![])
        );
    }
}
