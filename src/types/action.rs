//! Action entities for Cedar policies.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::cedar_type::CedarType;
use super::qualified_id::ActionId;
use super::resource::split_string_into_cedar_parts;

/// An action, possibly with a namespace (e.g. Infra::Action::"delete_vm").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Action {
    #[serde(flatten)]
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
        CedarType::Action.as_ref()
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
        match parts.type_part.as_deref() {
            Some(tp) if tp != expected => {
                return Err(PolicyError::InvalidFormat(format!(
                    "Failed to parse action: expected type '{expected}', found type '{tp}' in '{s}' (expected format: [Namespace::]*Action::action_id)"
                )));
            }
            _ => {}
        }

        Ok(Action::new(parts.id, parts.namespace))
    }
}

// Intentionally omit `From<String>` to avoid silently swallowing parse errors.

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
        assert_eq!(action.cedar_id(), quote_last_element(action_str));
    }

    fn some_str_to_string(input: Option<Vec<&str>>) -> Option<Vec<String>> {
        input.map(|v| v.into_iter().map(|s| s.to_string()).collect())
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
        assert_eq!(action.id, deserialized.id);
        assert_eq!(action, deserialized);
        assert_eq!(action.cedar_id(), deserialized.cedar_id());

        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(serialized);
        });
        assert_snapshot!(action.cedar_id());
    }

    #[test]
    fn test_fromstr_action_with_special_chars() {
        let action = Action::from_str(r#"Action::"create-host_v2""#).unwrap();
        assert_eq!(action.id.id(), "create-host_v2");
    }

    #[parameterized(
        action_rejects_user = { r#"User::"read""# },
        action_rejects_group = { r#"Group::"admins""# },
    )]
    fn test_fromstr_action_rejects_wrong_type(input: &str) {
        let result = Action::from_str(input);
        assert!(result.is_err());
        if let Err(PolicyError::InvalidFormat(msg)) = result {
            assert!(msg.contains("Action"));
        } else {
            panic!("Expected InvalidFormat error");
        }
    }
}
