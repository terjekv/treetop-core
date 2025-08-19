use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

use crate::models::{AttrValue, Resource};

pub trait Labeler: Send + Sync {
    /// e.g. "Host", "Database::Table"; you can also support wildcard/globs if you want.
    fn applies_to(&self, kind: &str) -> bool;
    /// Mutates the resource by injecting derived attributes (e.g., sets of labels)
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
    /// All previously loaded labelers will be replaced.
    pub fn load(&self, labelers: Vec<Arc<dyn Labeler>>) {
        self.inner.store(Arc::new(labelers));
    }
}

pub static LABEL_REGISTRY: Lazy<LabelRegistry> = Lazy::new(|| LabelRegistry {
    inner: ArcSwap::from_pointee(Vec::new()),
});
