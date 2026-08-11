//! Dependency-free helpers shared by the build script and its unit tests.

/// Extract the exact `cedar-policy` version from a Cargo manifest.
///
/// Cargo rewrites a source dependency such as
/// `cedar-policy = "=4.12.0"` into a `[dependencies.cedar-policy]` table when
/// it packages a crate. Supporting both representations keeps build metadata
/// correct in source checkouts and registry packages. Non-exact requirements
/// deliberately return `None`: they cannot identify the version Cargo resolved.
pub(crate) fn cedar_policy_version(manifest: &str) -> Option<String> {
    let mut table = "";

    for raw_line in manifest.lines() {
        let line = without_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            table = header.trim();
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches(['"', '\'']);

        if table == "dependencies" && key == "cedar-policy" {
            if let Some(version) = quoted_value(value) {
                return exact_version(version);
            }
            if let Some(version) = inline_table_version(value) {
                return exact_version(version);
            }
        }

        if matches!(
            table,
            "dependencies.cedar-policy" | "dependencies.\"cedar-policy\""
        ) && key == "version"
        {
            return quoted_value(value).and_then(exact_version);
        }
    }

    None
}

fn inline_table_version(value: &str) -> Option<&str> {
    let table = value.trim().strip_prefix('{')?.strip_suffix('}')?;
    table.split(',').find_map(|entry| {
        let (key, value) = entry.split_once('=')?;
        (key.trim().trim_matches(['"', '\'']) == "version")
            .then(|| quoted_value(value))
            .flatten()
    })
}

fn quoted_value(value: &str) -> Option<&str> {
    let value = value.trim();
    let quote = value.chars().next()?;
    if !matches!(quote, '"' | '\'') {
        return None;
    }

    let remainder = &value[quote.len_utf8()..];
    let mut escaped = false;
    for (index, character) in remainder.char_indices() {
        if quote == '"' && character == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if character == quote && !escaped {
            return Some(&remainder[..index]);
        }
        escaped = false;
    }
    None
}

fn exact_version(version: &str) -> Option<String> {
    let version = version.trim().strip_prefix('=')?.trim();
    (!version.is_empty()).then(|| version.to_string())
}

fn without_comment(line: &str) -> &str {
    let mut basic_string = false;
    let mut literal_string = false;
    let mut escaped = false;

    for (index, character) in line.char_indices() {
        match character {
            '\\' if basic_string && !escaped => {
                escaped = true;
                continue;
            }
            '"' if !literal_string && !escaped => basic_string = !basic_string,
            '\'' if !basic_string => literal_string = !literal_string,
            '#' if !basic_string && !literal_string => return &line[..index],
            _ => {}
        }
        escaped = false;
    }
    line
}

#[cfg(test)]
mod tests {
    use super::cedar_policy_version;

    #[test]
    fn parses_source_string_dependency() {
        let manifest = r#"
            [dependencies]
            cedar-policy = "=4.12.0"
        "#;
        assert_eq!(cedar_policy_version(manifest).as_deref(), Some("4.12.0"));
    }

    #[test]
    fn parses_source_inline_dependency() {
        let manifest = r#"
            [dependencies]
            cedar-policy = { version = "=4.12.0", features = ["partial-eval"] }
        "#;
        assert_eq!(cedar_policy_version(manifest).as_deref(), Some("4.12.0"));
    }

    #[test]
    fn parses_cargo_normalized_dependency_table() {
        let manifest = r#"
            [package]
            version = "0.0.18"

            [dependencies.cedar-policy]
            version = "=4.12.0"
        "#;
        assert_eq!(cedar_policy_version(manifest).as_deref(), Some("4.12.0"));
    }

    #[test]
    fn rejects_a_compatible_version_requirement() {
        let manifest = r#"
            [dependencies]
            cedar-policy = "4.12"
        "#;
        assert_eq!(cedar_policy_version(manifest), None);
    }

    #[test]
    fn parses_current_source_manifest() {
        assert_eq!(
            cedar_policy_version(include_str!("Cargo.toml")).as_deref(),
            Some("4.12.0")
        );
    }
}
