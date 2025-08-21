#![allow(dead_code)]

use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub crate_name: &'static str,
    pub crate_url: &'static str,
    pub crate_version: &'static str,
    pub version: String,
    pub git: Option<GitInfo>,
    pub rustc_semver: Option<&'static str>,
    pub target_triple: Option<&'static str>,
    pub profile: Option<&'static str>,
    pub build_unix: Option<i64>,
    pub cedar_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitInfo {
    pub describe: &'static str,
    pub branch: &'static str,
    pub sha: &'static str,
    pub dirty: bool,
}

fn non_idempotent(s: Option<&'static str>) -> &'static str {
    match s {
        Some("VERGEN_IDEMPOTENT_OUTPUT") | None => "",
        Some(v) => v,
    }
}

static CELL: OnceLock<BuildInfo> = OnceLock::new();

pub fn build_info() -> &'static BuildInfo {
    CELL.get_or_init(|| {
        let pkg_name = env!("CARGO_PKG_NAME");
        let pkg_ver = env!("CARGO_PKG_VERSION");
        let dependencies = env!("VERGEN_CARGO_DEPENDENCIES")
            .split(',')
            .collect::<Vec<_>>();

        let cedar_version = dependencies
            .iter()
            .find(|&&dep| dep.starts_with("cedar-policy"))
            .map(|dep| dep.split_whitespace().nth(1).unwrap_or(""))
            .unwrap_or("default");

        let crate_url = option_env!("CARGO_PKG_REPOSITORY").unwrap_or("");

        let describe = non_idempotent(option_env!("VERGEN_GIT_DESCRIBE"));
        let sha = non_idempotent(option_env!("VERGEN_GIT_SHA"));
        let branch = non_idempotent(option_env!("VERGEN_GIT_BRANCH"));
        let dirty = option_env!("VERGEN_GIT_DIRTY").unwrap_or("false") == "true";

        let version = format_human_version(pkg_ver, describe, dirty);
        let build_unix = option_env!("VERGEN_BUILD_TIMESTAMP").and_then(|s| s.parse().ok());

        let git = if describe != "" {
            Some(GitInfo {
                describe,
                sha,
                branch,
                dirty,
            })
        } else {
            None
        };

        BuildInfo {
            crate_name: pkg_name,
            crate_url,
            crate_version: pkg_ver,
            version,
            git,
            rustc_semver: option_env!("VERGEN_RUSTC_SEMVER"),
            target_triple: option_env!("VERGEN_CARGO_TARGET_TRIPLE"),
            profile: option_env!("VERGEN_CARGO_PROFILE"),
            build_unix,
            cedar_version,
        }
    })
}

pub fn format_human_version(pkg_ver: &str, git_describe_input: &str, git_dirty: bool) -> String {
    if git_describe_input.is_empty() {
        // No git info available (published crate, source tarball, etc.)
        return pkg_ver.to_string();
    }
    let mut git_describe = git_describe_input;
    if git_describe.ends_with("-dirty") {
        git_describe = &git_describe[..git_describe.len() - "-dirty".len()];
    }
    let dirty = if git_dirty { "-dirty" } else { "" };

    fn looks_like_sha(s: &str) -> bool {
        let s = s.strip_prefix('g').unwrap_or(s);
        s.len() >= 7 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    let parts: Vec<&str> = git_describe.split('-').collect();
    if parts.len() >= 3 {
        let maybe_dist = parts[parts.len() - 2];
        let maybe_sha = parts[parts.len() - 1];
        if maybe_dist.parse::<u64>().is_ok() && looks_like_sha(maybe_sha) {
            let tag = parts[..parts.len() - 2].join("-");
            let short = maybe_sha.strip_prefix('g').unwrap_or(maybe_sha);
            return format!("{tag}+{maybe_dist}.g{short}{dirty}");
        }
    }

    if looks_like_sha(git_describe) {
        let short = git_describe.strip_prefix('g').unwrap_or(git_describe);
        return format!("0.0.0+g{short}{dirty}");
    }

    let tag_ign_v = git_describe.trim_start_matches('v');
    if tag_ign_v == pkg_ver {
        return format!("v{tag_ign_v}{dirty}");
    }
    format!("{git_describe}{dirty}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_values() {
        let build_info = build_info();
        assert_eq!(build_info.crate_name, "treetop-core");
    }
}
