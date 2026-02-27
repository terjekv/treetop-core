//! Request context values passed to Cedar evaluation.

use std::collections::BTreeMap;

use cedar_policy::Context;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::PolicyError;

use super::AttrValue;

/// Typed wrapper for request context attributes.
///
/// Context values are passed to Cedar as restricted expressions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct RequestContext(BTreeMap<String, AttrValue>);

impl RequestContext {
    /// Create an empty request context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one context attribute and return the updated context.
    pub fn with_attr(mut self, key: impl Into<String>, value: AttrValue) -> Self {
        self.0.insert(key.into(), value);
        self
    }

    /// Insert one context attribute.
    pub fn insert(&mut self, key: impl Into<String>, value: AttrValue) -> Option<AttrValue> {
        self.0.insert(key.into(), value)
    }

    /// Returns true when there are no context attributes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of context attributes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over context attributes.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &AttrValue)> {
        self.0.iter()
    }

    /// Convert to a Cedar `Context`.
    pub fn to_cedar_context(&self) -> Result<Context, PolicyError> {
        Context::from_pairs(
            self.0
                .iter()
                .map(|(k, v)| (k.clone(), v.to_re()))
                .collect::<Vec<_>>(),
        )
        .map_err(Into::into)
    }
}

impl From<BTreeMap<String, AttrValue>> for RequestContext {
    fn from(value: BTreeMap<String, AttrValue>) -> Self {
        Self(value)
    }
}

impl From<RequestContext> for BTreeMap<String, AttrValue> {
    fn from(value: RequestContext) -> Self {
        value.0
    }
}

impl<'a> IntoIterator for &'a RequestContext {
    type Item = (&'a String, &'a AttrValue);
    type IntoIter = std::collections::btree_map::Iter<'a, String, AttrValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_to_cedar_context() {
        let context = RequestContext::new()
            .with_attr("ticket", AttrValue::Long(42))
            .with_attr("env", AttrValue::String("prod".into()));

        let cedar_context = context.to_cedar_context().unwrap();
        assert_eq!(cedar_context.get("ticket").unwrap().to_string(), "42");
        assert_eq!(cedar_context.get("env").unwrap().to_string(), "\"prod\"");
    }

    #[test]
    fn test_request_context_insert_and_len() {
        let mut context = RequestContext::new();
        assert!(context.is_empty());

        context.insert("a", AttrValue::Bool(true));
        context.insert("b", AttrValue::Long(1));

        assert_eq!(context.len(), 2);
    }
}
