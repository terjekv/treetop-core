//! Resource entities for Cedar policies.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use cedar_policy::{EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::traits::CedarAtom;

use super::attr_value::AttrValue;
use super::cedar_type::CedarType;
use super::uid_cache::EntityUidCache;

pub(super) struct CedarParts {
    pub id: String,
    pub type_part: Option<String>,
    pub namespace: Option<Vec<String>>,
}

pub(super) fn split_string_into_cedar_parts(s: &str) -> Result<CedarParts, PolicyError> {
    let input = s.trim();
    if input.is_empty() {
        return Err(PolicyError::InvalidFormat(
            "entity identifier cannot be empty".to_string(),
        ));
    }

    if let Ok(uid) = input.parse::<EntityUid>() {
        if uid.id().unescaped().is_empty() {
            return Err(PolicyError::InvalidFormat(
                "entity identifier cannot be empty".to_string(),
            ));
        }
        let type_name = uid.type_name();
        let namespace = type_name
            .namespace_components()
            .map(str::to_string)
            .collect::<Vec<_>>();
        return Ok(CedarParts {
            id: uid.id().unescaped().to_string(),
            type_part: Some(type_name.basename().to_string()),
            namespace: (!namespace.is_empty()).then_some(namespace),
        });
    }

    if !input.contains("::") {
        if input.contains(['"', '\\']) {
            return Err(PolicyError::InvalidFormat(format!(
                "unqualified entity identifier contains invalid quoting: '{input}'"
            )));
        }
        return Ok(CedarParts {
            id: input.to_string(),
            type_part: None,
            namespace: None,
        });
    }

    // Preserve the historical unquoted-ID shorthand while using Cedar's type
    // parser for the namespaced type. Quoted inputs must parse as a complete
    // Cedar EntityUid above; never try to repair malformed quoting here.
    let (type_path, id) = input.rsplit_once("::").ok_or_else(|| {
        PolicyError::InvalidFormat(format!("invalid Cedar entity identifier: '{input}'"))
    })?;
    if id.is_empty() || id.contains(['"', '\\']) {
        return Err(PolicyError::InvalidFormat(format!(
            "invalid unquoted entity identifier in '{input}'"
        )));
    }
    let type_name: EntityTypeName = type_path.parse().map_err(|e| {
        PolicyError::InvalidFormat(format!("invalid Cedar entity type in '{input}': {e}"))
    })?;
    let namespace = type_name
        .namespace_components()
        .map(str::to_string)
        .collect::<Vec<_>>();

    Ok(CedarParts {
        id: id.to_string(),
        type_part: Some(type_name.basename().to_string()),
        namespace: (!namespace.is_empty()).then_some(namespace),
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
    #[serde(skip)]
    uid_cache: EntityUidCache,
}

impl Display for Resource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            r#"{}::"{}""#,
            self.kind,
            EntityId::new(&self.id).escaped()
        )
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

        let kind = match parts.namespace {
            Some(namespace) => format!("{}::{kind}", namespace.join("::")),
            None => kind,
        };

        Ok(Resource::new(kind, parts.id))
    }
}

impl Resource {
    /// Create a new resource with `kind` and `id`.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            attrs: BTreeMap::new(),
            uid_cache: EntityUidCache::default(),
        }
    }

    /// Add an attribute to the resource, returning the updated value.
    ///
    /// For `AttrValue::Set`, values are stored as-is; duplicates are not
    /// automatically de-duplicated. The `id` key is reserved: Cedar entity
    /// construction always replaces it with the resource's canonical ID.
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

    /// Borrow the resource attributes without allowing mutation.
    pub fn attributes(&self) -> &BTreeMap<String, AttrValue> {
        &self.attrs
    }
}

impl CedarAtom for Resource {
    fn cedar_type() -> &'static str {
        CedarType::Resource.as_ref()
    }

    fn cedar_id(&self) -> String {
        format!(r#"{}::"{}""#, self.kind, EntityId::new(&self.id).escaped())
    }

    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        self.uid_cache.get_or_build(|| {
            if self.id.is_empty() {
                return Err(PolicyError::InvalidFormat(
                    "resource identifier cannot be empty".to_string(),
                ));
            }
            let type_name: EntityTypeName = self.kind.parse().map_err(|e| {
                PolicyError::InvalidFormat(format!("invalid resource type '{}': {e}", self.kind))
            })?;
            Ok(EntityUid::from_type_name_and_id(
                type_name,
                EntityId::new(&self.id),
            ))
        })
    }

    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        let mut m = HashMap::with_capacity(self.attrs.len() + 1);
        for (k, v) in &self.attrs {
            m.insert(k.clone(), v.to_re());
        }
        // `id` is server-derived from the entity identity. Insert it last so
        // caller-provided attributes cannot forge the canonical value.
        m.insert(
            "id".to_string(),
            RestrictedExpression::new_string(self.id.clone()),
        );
        Ok(m)
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

    #[test]
    fn test_fromstr_preserves_namespaced_resource_type() {
        let resource = Resource::from_str(r#"Database::Table::"users""#).unwrap();
        assert_eq!(resource.kind(), "Database::Table");
        assert_eq!(resource.id(), "users");
        assert_eq!(resource.cedar_id(), r#"Database::Table::"users""#);
    }

    #[test]
    fn test_fromstr_handles_escaped_and_namespaced_ids() {
        let resource = Resource::from_str(r#"Database::Table::"users::\"archive\"""#).unwrap();
        assert_eq!(resource.kind(), "Database::Table");
        assert_eq!(resource.id(), "users::\"archive\"");
        assert_eq!(
            resource.cedar_id(),
            r#"Database::Table::"users::\"archive\"""#
        );
    }

    #[test]
    fn test_fromstr_rejects_malformed_resource() {
        for input in ["", "Host::", r#"Host::"unterminated"#] {
            assert!(Resource::from_str(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn caller_cannot_override_canonical_id_attribute() {
        let resource =
            Resource::new("Host", "canonical").with_attr("id", AttrValue::String("forged".into()));

        let attrs = resource.cedar_attr().unwrap();
        assert_eq!(
            attrs["id"],
            RestrictedExpression::new_string("canonical".to_string())
        );
    }
}
