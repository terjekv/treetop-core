//! Cedar entity type names and related constants.
//!
//! This module centralizes Cedar type definitions to reduce magic strings
//! throughout the codebase and provide a single source of truth for type names.

/// The standard Cedar entity types used in Treetop policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CedarType {
    /// A user principal (e.g., `User::"alice"`)
    User,
    /// A group principal (e.g., `Group::"admins"`)
    Group,
    /// A principal (either `User` or `Group`)
    Principal,
    /// An action (e.g., `Action::"create_host"`)
    Action,
    /// A resource (e.g., `Resource::"Host"`)
    Resource,
}

impl AsRef<str> for CedarType {
    fn as_ref(&self) -> &str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::Principal => "Principal",
            Self::Action => "Action",
            Self::Resource => "Resource",
        }
    }
}

impl std::str::FromStr for CedarType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "User" => Ok(Self::User),
            "Group" => Ok(Self::Group),
            "Principal" => Ok(Self::Principal),
            "Action" => Ok(Self::Action),
            "Resource" => Ok(Self::Resource),
            _ => Err(format!("Unknown Cedar type: {}", s)),
        }
    }
}

impl std::fmt::Display for CedarType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cedar_type_as_ref() {
        assert_eq!(CedarType::User.as_ref(), "User");
        assert_eq!(CedarType::Group.as_ref(), "Group");
        assert_eq!(CedarType::Principal.as_ref(), "Principal");
        assert_eq!(CedarType::Action.as_ref(), "Action");
        assert_eq!(CedarType::Resource.as_ref(), "Resource");
    }

    #[test]
    fn test_cedar_type_from_str() {
        use std::str::FromStr;
        assert_eq!(CedarType::from_str("User").unwrap(), CedarType::User);
        assert_eq!(CedarType::from_str("Group").unwrap(), CedarType::Group);
        assert_eq!(CedarType::from_str("Principal").unwrap(), CedarType::Principal);
        assert_eq!(CedarType::from_str("Resource").unwrap(), CedarType::Resource);
        assert_eq!(CedarType::from_str("Action").unwrap(), CedarType::Action);
        assert!(CedarType::from_str("Unknown").is_err());
    }

    #[test]
    fn test_cedar_type_display() {
        assert_eq!(CedarType::User.to_string(), "User");
        assert_eq!(CedarType::Group.to_string(), "Group");
        assert_eq!(CedarType::Principal.to_string(), "Principal");
        assert_eq!(CedarType::Action.to_string(), "Action");
        assert_eq!(CedarType::Resource.to_string(), "Resource");
    }
}
