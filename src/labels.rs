use arc_swap::ArcSwap;
use regex::Regex;
use std::sync::Arc;

use crate::types::{AttrValue, Resource};

/// Trait for objects that can label resources based on their attributes.
///
/// Implementations should be fast and side-effect free beyond mutating the
/// provided `Resource`'s attributes. Repeated application must be safe and
/// idempotent. A labeler owns the attributes it derives: it must replace or
/// remove preexisting values instead of trusting caller-provided output.
pub trait Labeler: Send + Sync {
    /// Returns true if this labeler applies to resources of the given kind.
    ///
    /// e.g. "Host", "Database::Table"; you can also support wildcard/globs if you want.
    fn applies_to(&self, kind: &str) -> bool;

    /// Mutates the resource by injecting derived attributes (e.g., sets of labels).
    fn apply(&self, res: &mut Resource);
}

/// A labeler that uses regular expressions for matching on resource attributes.
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
    ///
    /// Configure `field` and `output` as distinct attributes so repeated
    /// application remains idempotent. `field` reads the resource attribute
    /// map; it does not expose canonical entity fields. In particular, an
    /// attribute named `id` is not the canonical [`Resource::id`] value during
    /// labeling. Use a custom [`Labeler`] that reads [`Resource::id`] when
    /// labels must derive from the resource identity.
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
        let Some(AttrValue::String(value)) = res.attributes().get(&self.field) else {
            // The output is derived and therefore must never preserve a value
            // supplied by the caller when its trusted input is unavailable.
            res.attrs().remove(&self.output);
            return;
        };
        let out = self
            .table
            .iter()
            .filter(|(_, re)| re.is_match(value))
            .map(|(label, _)| AttrValue::String(label.clone()))
            .collect();

        // Replace even when the result is empty. Retaining or extending a
        // caller-provided set would make a derived authorization label
        // forgeable.
        res.attrs().insert(self.output.clone(), AttrValue::Set(out));
    }
}

/// Implementation of the LabelRegistry.
///
/// Consumption of this registry goes through the static `LABEL_REGISTRY`.
pub struct LabelRegistry {
    inner: ArcSwap<Vec<Arc<dyn Labeler>>>,
}
impl LabelRegistry {
    /// Clone and label a resource only when at least one labeler applies.
    ///
    /// The first matching labeler is found before cloning so registries that
    /// serve other resource kinds add no resource-clone cost. Each labeler's
    /// applicability predicate is still evaluated at most once and labelers
    /// retain insertion order.
    pub(crate) fn apply_to_clone_if_applicable(&self, res: &Resource) -> Option<Resource> {
        let snapshot = self.inner.load();
        let first_match = snapshot
            .iter()
            .position(|labeler| labeler.applies_to(res.kind()))?;

        let mut labelled = res.clone();
        snapshot[first_match].apply(&mut labelled);
        for labeler in &snapshot[first_match + 1..] {
            if labeler.applies_to(labelled.kind()) {
                labeler.apply(&mut labelled);
            }
        }
        Some(labelled)
    }

    /// Applies all labelers in the registry to the given resource.
    ///
    /// Labelers run in insertion order. Each labeler owns its derived output;
    /// if multiple labelers target the same attribute, the last one wins.
    pub fn apply(&self, res: &mut Resource) {
        let snapshot = self.inner.load();
        for l in snapshot.iter() {
            if l.applies_to(res.kind()) {
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
    fn regex_labeler_replaces_untrusted_existing_set() {
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
        assert!(!labels.contains("pre"));
        assert!(labels.contains("prod"));
        assert!(labels.contains("db"));
    }

    #[test]
    fn regex_labeler_replaces_untrusted_set_when_no_rule_matches() {
        let labeler = RegexLabeler::new(
            "Host",
            "name",
            "nameLabels",
            compile(vec![("prod", r"(^|\.)prod\.")]),
        );
        let mut res = Resource::new("Host", "public.example.com")
            .with_attr("name", AttrValue::String("public.example.com".into()))
            .with_attr(
                "nameLabels",
                AttrValue::Set(vec![AttrValue::String("prod".into())]),
            );

        labeler.apply(&mut res);

        assert_eq!(
            res.attributes().get("nameLabels"),
            Some(&AttrValue::Set(Vec::new()))
        );
    }

    #[test]
    fn regex_labeler_removes_untrusted_output_when_input_is_missing() {
        let labeler = RegexLabeler::new(
            "Host",
            "name",
            "nameLabels",
            compile(vec![("prod", r"(^|\.)prod\.")]),
        );
        let mut res = Resource::new("Host", "public.example.com").with_attr(
            "nameLabels",
            AttrValue::Set(vec![AttrValue::String("prod".into())]),
        );

        labeler.apply(&mut res);

        assert!(!res.attributes().contains_key("nameLabels"));
    }
}
