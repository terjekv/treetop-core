use arc_swap::ArcSwap;
use regex::Regex;
use std::sync::Arc;

use crate::types::{AttrValue, Resource};

/// Trait for objects that can label resources based on their attributes.
///
/// Implementations should be fast and side-effect free beyond mutating the
/// provided `Resource`'s attributes. Repeated application should be safe and
/// ideally idempotent.
pub trait Labeler: Send + Sync {
    /// Returns true if this labeler applies to resources of the given kind.
    ///
    /// e.g. "Host", "Database::Table"; you can also support wildcard/globs if you want.
    fn applies_to(&self, kind: &str) -> bool;

    /// Mutates the resource by injecting derived attributes (e.g., sets of labels).
    fn apply(&self, res: &mut Resource);
}

/// A labeler that uses regular expressions for matching on resource attributes.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RegexLabeler {
    /// The kind of resource this labeler applies to, e.g. "Host"
    kind: String,
    /// attribute to read from, e.g. "name"
    field: String,
    /// attribute to write to, e.g. "nameLabels"
    output: String,
    /// Rulesets for matching resource attributes
    table: Vec<(String, Regex)>,
}

impl RegexLabeler {
    /// Create a regex-based labeler.
    ///
    /// - `kind`: resource kind this applies to (e.g., "Host")
    /// - `field`: attribute to read from (e.g., "name")
    /// - `output`: attribute to write labels to (e.g., "nameLabels")
    /// - `table`: vector of `(label, regex)` pairs
    #[allow(dead_code)]
    pub fn new(
        kind: impl Into<String>,
        field: impl Into<String>,
        output: impl Into<String>,
        table: Vec<(String, Regex)>,
    ) -> Self {
        Self {
            kind: kind.into(),
            field: field.into(),
            output: output.into(),
            table,
        }
    }
}

impl Labeler for RegexLabeler {
    fn applies_to(&self, kind: &str) -> bool {
        self.kind == kind
    }

    fn apply(&self, res: &mut Resource) {
        let Some(AttrValue::String(value)) = res.attrs().get(&self.field).cloned() else {
            return;
        };
        let mut out: Vec<AttrValue> = Vec::new();
        for (label, re) in &self.table {
            if re.is_match(&value) {
                out.push(AttrValue::String(label.clone()));
            }
        }
        if !out.is_empty() {
            match res.attrs().get_mut(&self.output) {
                Some(AttrValue::Set(existing)) => existing.extend(out),
                _ => {
                    res.attrs().insert(self.output.clone(), AttrValue::Set(out));
                }
            }
        }
    }
}

/// Implementation of the LabelRegistry.
///
/// Consumption of this registry goes through the static `LABEL_REGISTRY`.
pub struct LabelRegistry {
    inner: ArcSwap<Vec<Arc<dyn Labeler>>>,
}
impl LabelRegistry {
    /// Applies all labelers in the registry to the given resource.
    ///
    /// Labelers run in insertion order. If multiple labelers target the same
    /// output set attribute, values are appended.
    pub fn apply(&self, res: &mut Resource) {
        let snapshot = self.inner.load();
        let kind_owned = res.kind().to_owned();
        for l in snapshot.iter() {
            if l.applies_to(&kind_owned) {
                l.apply(res);
            }
        }
    }

    /// Loads a set of labelers into the registry, atomically.
    ///
    /// Replaces all prior labelers in a single swap. New `evaluate()` calls use
    /// the new set immediately; in-flight evaluations continue with the old set.
    pub fn reload(&self, labelers: Vec<Arc<dyn Labeler>>) {
        self.inner.store(Arc::new(labelers));
    }
}

/// Builder for creating a LabelRegistry with labelers.
///
/// This uses a builder pattern to ensure labelers are properly initialized
/// before the registry is used.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use treetop_core::{LabelRegistryBuilder, RegexLabeler};
/// use regex::Regex;
///
/// let registry = LabelRegistryBuilder::new()
///     .add_labeler(Arc::new(RegexLabeler::new(
///         "Host",
///         "name",
///         "nameLabels",
///         vec![("prod".to_string(), Regex::new(r"\.prod\.").unwrap())],
///     )))
///     .build();
/// ```
pub struct LabelRegistryBuilder {
    labelers: Vec<Arc<dyn Labeler>>,
}

impl LabelRegistryBuilder {
    /// Create a new, empty label registry builder.
    pub fn new() -> Self {
        Self {
            labelers: Vec::new(),
        }
    }

    /// Add a labeler to the registry.
    ///
    /// This can be called repeatedly to build up a registry before `build()`.
    pub fn add_labeler(mut self, labeler: Arc<dyn Labeler>) -> Self {
        self.labelers.push(labeler);
        self
    }

    /// Build the label registry.
    ///
    /// Consumes the builder and returns an initialized registry ready to use
    /// with `PolicyEngine::with_label_registry()`.
    pub fn build(self) -> LabelRegistry {
        LabelRegistry {
            inner: ArcSwap::from_pointee(self.labelers),
        }
    }
}

impl Default for LabelRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use yare::parameterized;

    fn compile(rules: Vec<(&str, &str)>) -> Vec<(String, Regex)> {
        rules
            .into_iter()
            .map(|(l, p)| (l.to_string(), Regex::new(p).unwrap()))
            .collect()
    }

    fn get_label_strings(res: &mut Resource, key: &str) -> BTreeSet<String> {
        match res.attrs().get(key) {
            Some(AttrValue::Set(v)) => v
                .iter()
                .filter_map(|a| {
                    if let AttrValue::String(s) = a {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    #[parameterized(
        simple_match = {
            "Host", "name", "nameLabels",
            vec![("prod", r"(^|\.)prod\.example\.com$")],
            "db12.prod.example.com",
            &["prod"]
        },
        no_match = {
            "Host", "name", "nameLabels",
            vec![("corp", r"(^|\.)corp\.example\.com$")],
            "web.dev.example.com",
            &[]
        },
        multi_match = {
            "Host", "name", "nameLabels",
            vec![("prod", r"(^|\.)prod\."), ("db", r"(^|\.)db\d+\.")],
            "db42.prod.example.com",
            &["db","prod"]
        }
    )]
    fn regex_labeler_apply_basic(
        kind: &str,
        field: &str,
        output: &str,
        rules: Vec<(&str, &str)>,
        input: &str,
        expected: &[&str],
    ) {
        let labeler = RegexLabeler::new(kind, field, output, compile(rules));

        let mut res = Resource::new(kind, input);
        res.attrs()
            .insert(field.to_string(), AttrValue::String(input.to_string()));

        labeler.apply(&mut res);

        let got = get_label_strings(&mut res, output);
        let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn regex_labeler_missing_input_field_is_noop() {
        let labeler = RegexLabeler::new(
            "Host",
            "name",
            "nameLabels",
            compile(vec![("prod", r"(^|\.)prod\.")]),
        );

        let mut res = Resource::new("Host", "db99.prod.example.com");
        // no "name" inserted

        labeler.apply(&mut res);
        assert!(res.attrs().get("nameLabels").is_none());
    }

    #[test]
    fn regex_labeler_appends_to_existing_set() {
        let labeler = RegexLabeler::new(
            "Host",
            "name",
            "nameLabels",
            compile(vec![("prod", r"(^|\.)prod\."), ("db", r"(^|\.)db\d+\.")]),
        );

        let mut res = Resource::new("Host", "db99.prod.example.com");
        res.attrs().insert(
            "name".into(),
            AttrValue::String("db99.prod.example.com".into()),
        );
        res.attrs().insert(
            "nameLabels".into(),
            AttrValue::Set(vec![AttrValue::String("pre".into())]),
        );

        labeler.apply(&mut res);

        let labels = get_label_strings(&mut res, "nameLabels");
        assert!(labels.contains("pre"));
        assert!(labels.contains("prod"));
        assert!(labels.contains("db"));
    }
}
