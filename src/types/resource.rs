//! Resource entities for Cedar policies.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use cedar_policy::{Context, EntityUid, RestrictedExpression};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::attr_value::AttrValue;
use super::cedar_type::CedarType;

pub(super) struct CedarParts<'a> {
    pub id: &'a str,
    pub type_part: Option<String>,
    pub namespace: Option<Vec<String>>,
}

pub(super) fn split_string_into_cedar_parts(s: &str) -> Result<CedarParts<'_>, PolicyError> {
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
            .ok_or_else(|| PolicyError::InvalidFormat(
                format!("Failed to parse resource: missing type in '{s}' (expected format: ResourceType::resource_id or Namespace::ResourceType::resource_id)")
            ))?;

        Ok(Resource::new(kind, parts.id.to_string()))
    }
}

impl Resource {
    /// Create a new resource with `kind` and `id`.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            attrs: BTreeMap::new(),
        }
    }

    /// Add an attribute to the resource, returning the updated value.
    ///
    /// For `AttrValue::Set`, values are stored as-is; duplicates are not
    /// automatically de-duplicated.
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
        CedarType::Resource.as_ref()
    }

    fn cedar_id(&self) -> String {
        format!(r#"{}::"{}""#, self.kind, self.id)
    }

    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        let cedar_id = self.cedar_id();
        EntityUid::from_str(&cedar_id).map_err(|e| {
            PolicyError::ParseError(format!(
                "Failed to parse resource entity UID '{}': {}",
                cedar_id, e
            ))
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;
    use yare::parameterized;

    #[parameterized(
        resource_without_attributes = { "test_resource", "test_id", None },
        resource_with_attributes = { "test_resource", "test_id", Some(vec![("attr1", AttrValue::String("value1".to_string())), ("attr2", AttrValue::Ip("10.0.0.1".to_string()))]) },
    )]
    fn assert_resource_serialization(kind: &str, id: &str, attrs: Option<Vec<(&str, AttrValue)>>) {
        let mut resource = Resource::new(kind, id);
        if let Some(attrs) = attrs {
            for (k, v) in attrs {
                resource.attrs.insert(k.to_string(), v);
            }
        }

        let serialized = serde_json::to_value(&resource).unwrap();
        let deserialized: Resource = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(resource.kind(), deserialized.kind());
        assert_eq!(resource, deserialized);
        assert_eq!(resource.cedar_id(), deserialized.cedar_id());

        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(serialized);
        });
        assert_snapshot!(resource.cedar_id());
    }

    #[test]
    fn test_fromstr_resource_with_colon_in_id() {
        let resource = Resource::from_str(r#"Host::"web-01:8080""#).unwrap();
        assert_eq!(resource.id(), "web-01:8080");
    }

    #[test]
    fn test_resource_kind_with_double_colon() {
        let resource = Resource::new("Database::Table", "users");
        assert_eq!(resource.kind(), "Database::Table");
    }
}
