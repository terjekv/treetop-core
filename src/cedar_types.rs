/// Cedar entity type names and related constants.
///
/// This module centralizes Cedar type definitions to reduce magic strings
/// throughout the codebase and provide a single source of truth for type names.

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

impl CedarType {
    /// Get the Cedar type name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::Principal => "Principal",
            Self::Action => "Action",
            Self::Resource => "Resource",
        }
    }

    /// Parse a string into a Cedar type.
    ///
    /// Returns `None` if the string doesn't match any known Cedar type.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "User" => Some(Self::User),
            "Group" => Some(Self::Group),
            "Principal" => Some(Self::Principal),
            "Action" => Some(Self::Action),
            "Resource" => Some(Self::Resource),
            _ => None,
        }
    }
}

impl std::fmt::Display for CedarType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cedar_type_as_str() {
        assert_eq!(CedarType::User.as_str(), "User");
        assert_eq!(CedarType::Group.as_str(), "Group");
        assert_eq!(CedarType::Principal.as_str(), "Principal");
        assert_eq!(CedarType::Action.as_str(), "Action");
        assert_eq!(CedarType::Resource.as_str(), "Resource");
    }

    #[test]
    fn test_cedar_type_from_str() {
        assert_eq!(CedarType::from_str("User"), Some(CedarType::User));
        assert_eq!(CedarType::from_str("Group"), Some(CedarType::Group));
        assert_eq!(CedarType::from_str("Principal"), Some(CedarType::Principal));
        assert_eq!(CedarType::from_str("Resource"), Some(CedarType::Resource));
        assert_eq!(CedarType::from_str("Action"), Some(CedarType::Action));
        assert_eq!(CedarType::from_str("Unknown"), None);
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
