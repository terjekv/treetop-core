use once_cell::sync::Lazy;
use regex::Regex;
use std::{sync::Arc, sync::RwLock};

use crate::models::{AttrValue, Resource};

pub trait Labeler: Send + Sync {
    /// e.g. "Host", "Database::Table"; you can also support wildcard/globs if you want.
    fn applies_to(&self, kind: &str) -> bool;
    /// Mutates the resource by injecting derived attributes (e.g., sets of labels)
    fn apply(&self, res: &mut Resource);
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RegexLabeler {
    kind: String,
    /// attribute to read from, e.g. "name"
    field: String,
    /// attribute to write to, e.g. "nameLabels"
    output: String,
    table: Vec<(String, Regex)>, // (label, pattern)
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

static LABELERS: Lazy<RwLock<Vec<Arc<dyn Labeler>>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub fn register_labeler<L: Labeler + 'static>(l: L) {
    LABELERS.write().unwrap().push(Arc::new(l));
}

pub fn apply_all_labels(res: &mut Resource) {
    for l in LABELERS.read().unwrap().iter() {
        if l.applies_to(&res.kind()) {
            l.apply(res);
        }
    }
}
