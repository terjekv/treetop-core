use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;
use std::str::FromStr;

use itertools::Itertools;

use cedar_policy::{ActionConstraint, Context, EntityUid, Policy, RestrictedExpression};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use utoipa::ToSchema;

/// A principal for a policy query.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
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

/// The API-level request, with strongly-typed principal, action, groups, resource, and context.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "value")]
pub enum AttrValue {
    String(String),
    Bool(bool),
    Long(i64),
    Ip(String),
    #[schema(no_recursion)]
    Set(Vec<AttrValue>), // typically Set<String>; we accept nested AttrValue for convenience
}

impl AttrValue {
    pub fn to_re(&self) -> RestrictedExpression {
        use RestrictedExpression as RE;
        match self {
            AttrValue::String(s) => RE::new_string(s.clone()),
            AttrValue::Bool(b) => RE::new_bool(*b),
            AttrValue::Long(n) => RE::new_long(*n),
            AttrValue::Ip(s) => RE::new_ip(s.clone()), // "192.0.2.1" or "10.0.0.0/8"
            AttrValue::Set(xs) => RE::new_set(xs.iter().map(|x| x.to_re())),
        }
    }
}

/// A resource entity in the Cedar policy model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Resource {
    /// Entity type, possibly namespaced: e.g. "Host", "Gateway", or "Database::Table"
    kind: String,
    /// Entity id (quotes are added when rendering the Cedar literal)
    id: String,
    /// Arbitrary attributes to attach to the resource entity
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attrs: BTreeMap<String, AttrValue>,
}

impl Display for Resource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, r#"{}::"{}""#, self.kind, self.id)
    }
}

impl FromStr for Resource {
    type Err = PolicyError;

    /// Accepts:
    /// - Host::web-01.example.com
    /// - Host::"web-01.example.com"
    /// - Database::Table::"users"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // reuse your split_string_into_cedar_parts
        let parts = split_string_into_cedar_parts(s)?;
        let kind = parts
            .type_part
            .ok_or_else(|| PolicyError::InvalidFormat(format!("Missing type in `{s}`")))?;

        Ok(Resource::new(kind, parts.id.to_string()))
    }
}

impl Resource {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            attrs: BTreeMap::new(),
        }
    }

    pub fn with_attr(mut self, k: impl Into<String>, v: AttrValue) -> Self {
        self.attrs.insert(k.into(), v);
        self
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn attrs(&mut self) -> &mut BTreeMap<String, AttrValue> {
        &mut self.attrs
    }
}

impl CedarAtom for Resource {
    fn cedar_type() -> &'static str {
        "Resource"
    }

    fn cedar_id(&self) -> String {
        format!(r#"{}::"{}""#, self.kind, self.id)
    }

    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        EntityUid::from_str(&self.cedar_id()).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        let mut m = HashMap::with_capacity(self.attrs.len() + 1);
        // It's often convenient to always expose `id` as an attribute too:
        m.insert(
            "id".to_string(),
            RestrictedExpression::new_string(self.id.clone()),
        );
        for (k, v) in &self.attrs {
            m.insert(k.clone(), v.to_re());
        }
        Ok(m)
    }

    // Resource-level context is optional now; leave empty by default.
    fn cedar_ctx(&self) -> Result<Context, PolicyError> {
        Ok(Context::empty())
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
    qid: String,
    namespace: Vec<String>,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> QualifiedId<T> {
    /// Construct from its parts.  Guaranteed valid by signature.
    pub fn new(id: impl Into<String>, namespace: Option<Vec<String>>) -> Self {
        QualifiedId {
            qid: id.into(),
            namespace: namespace.unwrap_or_default(),
            _marker: PhantomData,
        }
    }

    /// Get the raw id.
    pub fn id(&self) -> &str {
        &self.qid
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
            id = self.qid,
            parts = parts,
            ty = ty
        )
    }
}

impl<T> Display for QualifiedId<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // We don't know `T`'s name here; we'll implement Display on the wrappers.
        write!(f, "{}", self.qid)
    }
}

/// A User’s fully‐qualified ID.
pub type UserId = QualifiedId<UserMarker>;
/// A Group’s fully‐qualified ID.
pub type GroupId = QualifiedId<GroupMarker>;
/// An Action’s fully‐qualified ID.
pub type ActionId = QualifiedId<ActionMarker>;

/// A user principal, possibly with a namespace (e.g. Application::User::"alice").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct User {
    #[serde(flatten)]
    qid: UserId,
    groups: Groups,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.qid.fmt_qualified(Self::cedar_type()))
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
            qid: UserId::new(id, namespace.clone()),
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
        self.qid.fmt_qualified(Self::cedar_type())
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Action {
    #[serde(flatten)]
    qid: ActionId,
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.qid.fmt_qualified(Self::cedar_type()))
    }
}

impl Action {
    /// Create a new action with an optional namespace.
    pub fn new<T: Into<String>>(id: T, namespace: Option<Vec<String>>) -> Self {
        Action {
            qid: ActionId::new(id, namespace),
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
        self.qid.fmt_qualified(Self::cedar_type())
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Group {
    #[serde(flatten)]
    qid: GroupId,
}

impl Group {
    /// Create a new group with an optional namespace.
    pub fn new<S: AsRef<str>>(name: S, namespace: Option<Vec<String>>) -> Self {
        Group {
            qid: GroupId::new(name.as_ref(), namespace),
        }
    }
}

impl Display for Group {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.qid.fmt_qualified(Self::cedar_type()))
    }
}

impl CedarAtom for Group {
    fn cedar_type() -> &'static str {
        "Group"
    }

    fn cedar_id(&self) -> String {
        self.qid.fmt_qualified(Self::cedar_type())
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
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
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
        let group_names: Vec<String> = self.0.iter().map(|g| g.qid.id().to_string()).collect();
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
    use insta::{assert_json_snapshot, assert_snapshot};
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

        assert_eq!(user.qid.fmt_qualified("User"), quote_last_element(target));

        assert_eq!(user.qid.id(), expected_id);
        assert_eq!(
            user.groups
                .0
                .iter()
                .map(|g| g.qid.to_string())
                .collect::<Vec<_>>(),
            expected_groups.unwrap_or_default()
        );
        assert_eq!(
            user.qid.namespace(),
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
        assert_eq!(action.qid.id(), expected_id);
        assert_eq!(
            action.qid.fmt_qualified("Action"),
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
        assert_eq!(group.qid.id(), expected_id);
        assert_eq!(
            group.qid.fmt_qualified("Group"),
            quote_last_element(group_str)
        );
        assert_eq!(
            group.qid.namespace(),
            expected_namespace.as_deref().unwrap_or(&vec![])
        );
    }

    fn some_str_to_string(input: Option<Vec<&str>>) -> Option<Vec<String>> {
        input.map(|v| v.into_iter().map(|s| s.to_string()).collect())
    }

    #[parameterized(
        user_without_groups_and_namespace = { "test_user", None, None },
        user_with_one_group_and_one_namespace = { "test_user", Some(vec!["group1"]), Some(vec!["namespace1"]) },
        user_with_groups_and_namespace = { "test_user", Some(vec!["group1", "group2"]), Some(vec!["namespace1"]) },
        user_with_groups_and_namespaces = { "test_user", Some(vec!["group1", "group2"]), Some(vec!["namespace1", "namespace2"]) },

    )]
    fn test_user_serialization(
        user_str: &str,
        expected_groups: Option<Vec<&str>>,
        expected_namespace: Option<Vec<&str>>,
    ) {
        let groups = some_str_to_string(expected_groups);
        let namespaces = some_str_to_string(expected_namespace);

        let user = User::new(user_str, groups, namespaces);
        let serialized = serde_json::to_value(&user).unwrap();
        let deserialized: User = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(user.qid, deserialized.qid);
        assert_eq!(user, deserialized);
        assert_eq!(user.cedar_id(), deserialized.cedar_id());

        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(serialized);
            assert_snapshot!(user.cedar_id());
        });
    }

    #[parameterized(
        action_without_namespace = { "test_action", None },
        action_with_namespace = { "test_action", Some(vec!["namespace1"]) },
        action_with_multiple_namespaces = { "test_action", Some(vec!["namespace1", "namespace2"]) },
    )]
    fn assert_action_serialization(id: &str, namespaces: Option<Vec<&str>>) {
        let action = Action::new(id, some_str_to_string(namespaces));
        let serialized = serde_json::to_value(&action).unwrap();
        let deserialized: Action = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(action.qid, deserialized.qid);
        assert_eq!(action, deserialized);
        assert_eq!(action.cedar_id(), deserialized.cedar_id());

        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(serialized);
            assert_snapshot!(action.cedar_id());
        });
    }

    #[parameterized(
        resource_without_attributes = { "test_resource", "test_id", None },
        resource_with_attributes = { "test_resource", "test_id", Some(vec![("attr1", AttrValue::String("value1".to_string())), ("attr2", AttrValue::Ip("10.0.0.1".to_string()))]) },
    )]
    fn assert_resource_serialization(kind: &str, id: &str, attrs: Option<Vec<(&str, AttrValue)>>) {
        let mut resource = Resource::new(kind, id);
        if let Some(attrs) = attrs {
            for (key, value) in attrs {
                resource = resource.with_attr(key, value);
            }
        }

        let serialized = serde_json::to_value(&resource).unwrap();
        let deserialized: Resource = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(resource.kind(), deserialized.kind());
        assert_eq!(resource, deserialized);
        assert_eq!(resource.cedar_id(), deserialized.cedar_id());

        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(serialized);
            assert_snapshot!(resource.cedar_id());
        });
    }
}
