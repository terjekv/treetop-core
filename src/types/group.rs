//! Group entities and collections.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::cedar_type::CedarType;
use super::qualified_id::GroupId;
use super::resource::split_string_into_cedar_parts;

/// A group identifier (e.g. Group::"devs").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Group {
    #[serde(flatten)]
    pub(crate) id: GroupId,
}

impl Group {
    /// Create a new group with an optional namespace.
    pub fn new<S: AsRef<str>>(name: S, namespace: Option<Vec<String>>) -> Self {
        Group {
            id: GroupId::new(name.as_ref(), namespace),
        }
    }

    /// Get the group ID.
    pub fn id(&self) -> &GroupId {
        &self.id
    }
}

impl Display for Group {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.id.fmt_qualified(Self::cedar_type()))
    }
}

impl CedarAtom for Group {
    fn cedar_type() -> &'static str {
        CedarType::Group.as_ref()
    }

    fn cedar_id(&self) -> String {
        self.id.fmt_qualified(Self::cedar_type())
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
                    "Failed to parse group: expected type '{expected}', found type '{type_part}' in '{s}' (expected format: [Namespace::]*Group::group_id)"
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
    /// Construct a `Groups` list from names, with an optional shared namespace.
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
        let group_names: Vec<String> = self.0.iter().map(|g| g.id().id().to_string()).collect();
        write!(f, "[{}]", group_names.join(", "))
    }
}

impl Iterator for Groups {
    type Item = Group;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yare::parameterized;

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
        assert_eq!(group.id.id(), expected_id);
        assert_eq!(
            group.id.namespace().to_vec(),
            expected_namespace.unwrap_or_default()
        );
        assert_eq!(
            group.cedar_id(),
            quote_last_element(group_str)
        );
    }

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
        group_rejects_user = { r#"User::"admins""# },
        group_rejects_action = { r#"Action::"create""# },
    )]
    fn test_fromstr_group_rejects_wrong_type(input: &str) {
        let result = Group::from_str(input);
        assert!(result.is_err());
        if let Err(PolicyError::InvalidFormat(msg)) = result {
            assert!(msg.contains("Group"));
        } else {
            panic!("Expected InvalidFormat error");
        }
    }

    #[test]
    fn test_fromstr_group_with_special_chars() {
        let group = Group::from_str(r#"Group::"team-alpha_2024""#).unwrap();
        assert_eq!(group.id.id(), "team-alpha_2024");
    }

    #[test]
    fn test_groups_default() {
        let groups = Groups::default();
        assert!(groups.is_empty());
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_groups_display_multiple() {
        let groups = Groups::new(vec!["admins", "users"], None);
        let display = format!("{}", groups);
        // Order might vary due to iterator, but both should be present
        assert!(display.contains("admins"));
        assert!(display.contains("users"));
    }

    #[test]
    fn test_groups_iterator() {
        let groups = Groups::new(vec!["admins", "users", "developers"], None);
        let mut count = 0;
        for group in groups {
            count += 1;
            assert!(group.id().id() == "admins" || group.id().id() == "users" || group.id().id() == "developers");
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_groups_len() {
        let groups = Groups::new(vec!["a", "b", "c"], None);
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn test_groups_clone() {
        let groups = Groups::new(vec!["admins"], None);
        let cloned = groups.clone();
        assert_eq!(groups.len(), cloned.len());
    }

    #[test]
    fn test_groups_with_namespace() {
        let groups = Groups::new(vec!["admins"], Some(vec!["App".to_string()]));
        assert_eq!(groups.len(), 1);
        let display = format!("{}", groups);
        assert!(display.contains("admins"));
    }

    #[test]
    fn test_group_id_accessor() {
        let group = Group::new("admins", None);
        assert_eq!(group.id().id(), "admins");
    }

    #[test]
    fn test_group_serialization() {
        let group = Group::new("admins", Some(vec!["App".to_string()]));
        let serialized = serde_json::to_value(&group).unwrap();
        let deserialized: Group = serde_json::from_value(serialized).unwrap();
        assert_eq!(group.id().id(), deserialized.id().id());
    }

    #[test]
    fn test_groups_serialization() {
        let groups = Groups::new(vec!["admins", "users"], None);
        let serialized = serde_json::to_value(&groups).unwrap();
        let deserialized: Groups = serde_json::from_value(serialized).unwrap();
        assert_eq!(groups.len(), deserialized.len());
    }
}
