use once_cell::sync::Lazy;
use regex::Regex;
use std::{collections::HashMap, sync::RwLock};

/// A global static variable to hold host patterns, which is a mapping of labels to compiled regex patterns.
pub static HOST_PATTERNS: Lazy<RwLock<HashMap<String, Regex>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Initializes the global host patterns with the provided patterns.
///
/// # Arguments
///
/// `patterns`: An iterator of tuples where each tuple contains a label (String) and a compiled regex (Regex).
#[allow(dead_code)]
pub fn initialize_host_patterns(patterns: impl IntoIterator<Item = (String, Regex)>) {
    let mut reg = HOST_PATTERNS.write().unwrap();
    for (label, re) in patterns {
        reg.insert(label, re);
    }
}
