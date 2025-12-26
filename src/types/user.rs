//! User entities with group membership.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::cedar_type::CedarType;
use super::group::Groups;
use super::qualified_id::UserId;
use super::resource::split_string_into_cedar_parts;

/// A user principal, possibly with a namespace (e.g. Application::User::"alice").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct User {
    #[serde(flatten)]
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
        CedarType::User.as_ref()
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
                    "Failed to parse user: expected type '{expected}', found type '{type_part}' in '{s}' (expected format: [Namespace::]*User::user_id[group1,group2,...])"
                )));
            }
        }

        Ok(User::new(parts.id, groups, parts.namespace))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;
    use yare::parameterized;

    fn quote_last_element(s: &str) -> String {
        if s.contains("::") {
            let parts: Vec<&str> = s.split("::").collect();
            let last_part = parts.last().unwrap().trim_matches('"');
            format!("{}::\"{}\"", parts[..parts.len() - 1].join("::"), last_part)
        } else {
            s.to_string()
        }
    }

    #[parameterized(
        alice = { "User::alice", "alice", None, None },
        alice_with_groups = { "User::alice[admins,users]", "alice", Some(vec!["admins".to_string(), "users".to_string()]), None },
        alice_with_namespace = { "Infra::User::alice", "alice", None, Some(vec!["Infra".to_string()]) },
        alice_with_multiple_namespaces = { "Infra::Core::User::alice", "alice", None, Some(vec!["Infra".to_string(), "Core".to_string()]) },
        alice_with_groups_and_namespace = { "Infra::User::alice[admins,users]", "alice", Some(vec!["admins".to_string(), "users".to_string()]), Some(vec!["Infra".to_string()]) },
    )]
    #[allow(clippy::unnecessary_literal_unwrap)]
    fn test_user_from_str(
        user_str: &str,
        expected_id: &str,
        expected_groups: Option<Vec<String>>,
        expected_namespace: Option<Vec<String>>,
    ) {
        let user = User::from_str(user_str).unwrap();

        let target = if user_str.contains("[") {
            user_str.split('[').next().unwrap().trim()
        } else {
            user_str
        };

        assert_eq!(user.id.fmt_qualified("User"), quote_last_element(target));

        assert_eq!(user.id.id(), expected_id);
        assert_eq!(
            user.groups()
                .clone()
                .map(|g| g.id().id().to_string())
                .collect::<Vec<_>>()
                .len(),
            expected_groups.as_ref().map(|g| g.len()).unwrap_or(0)
        );
        assert_eq!(
            user.id.namespace().to_vec(),
            expected_namespace.unwrap_or_default()
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
        assert_eq!(user.id, deserialized.id);
        assert_eq!(user, deserialized);
        assert_eq!(user.cedar_id(), deserialized.cedar_id());

        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(serialized);
        });
        assert_snapshot!(user.cedar_id());
    }

    #[parameterized(
        user_with_email = { r#"User::"alice@example.com""#, "alice@example.com" },
        user_with_special_chars = { r#"User::"alice-smith_123""#, "alice-smith_123" },
        user_with_spaces = { r#"User::"Alice Smith""#, "Alice Smith" },
    )]
    fn test_fromstr_user_special_chars(input: &str, expected_id: &str) {
        let user = User::from_str(input).unwrap();
        assert_eq!(user.id.id(), expected_id);
    }

    #[parameterized(
        user_rejects_action = { r#"Action::"alice""# },
        user_rejects_group = { r#"Group::"admins""# },
    )]
    fn test_fromstr_user_rejects_wrong_type(input: &str) {
        let result = User::from_str(input);
        assert!(result.is_err());
        if let Err(PolicyError::InvalidFormat(msg)) = result {
            assert!(msg.contains("User"));
        } else {
            panic!("Expected InvalidFormat error");
        }
    }

    #[parameterized(
        user_malformed_no_id = { "User::", "" },
        user_no_type = { "alice", "alice" },
        user_empty_string = { "", "" },
    )]
    fn test_fromstr_edge_cases(input: &str, expected_id: &str) {
        let user = User::from_str(input).unwrap();
        assert_eq!(user.id.id(), expected_id);
    }

    #[test]
    fn test_fromstr_user_with_groups_and_special_chars() {
        let user = User::from_str(r#"User::"alice@example.com"[admins,users]"#).unwrap();
        assert_eq!(user.id.id(), "alice@example.com");
    }

    #[test]
    fn test_fromstr_deeply_nested_namespace() {
        let user = User::from_str("A::B::C::User::alice").unwrap();
        assert_eq!(user.id.namespace().len(), 3);
    }

    #[test]
    fn test_fromstr_namespace_with_numbers() {
        let user = User::from_str("NS1::NS2::User::alice").unwrap();
        assert_eq!(user.id.namespace(), &["NS1".to_string(), "NS2".to_string()]);
    }
}
