#![allow(dead_code)]

use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub crate_name: &'static str,
    pub crate_url: &'static str,
    pub crate_version: &'static str,
    pub version: String,
    pub git: GitInfo,
    pub rustc_semver: Option<&'static str>,
    pub target_triple: Option<&'static str>,
    pub profile: Option<&'static str>,
    pub build_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitInfo {
    pub describe: &'static str,
    pub branch: &'static str,
    pub sha: &'static str,
    pub dirty: bool,
}

static CELL: OnceLock<BuildInfo> = OnceLock::new();

pub fn build_info() -> &'static BuildInfo {
    CELL.get_or_init(|| {
        let pkg_name = env!("CARGO_PKG_NAME");
        let pkg_ver = env!("CARGO_PKG_VERSION");

        let describe = env!("VERGEN_GIT_DESCRIBE");
        let sha = env!("VERGEN_GIT_SHA");
        let branch = env!("VERGEN_GIT_BRANCH");
        let dirty = env!("VERGEN_GIT_DIRTY") == "true";
        let crate_url = env!("CARGO_PKG_REPOSITORY");

        let human = format_human_version(pkg_ver, describe, dirty);

        let build_unix = option_env!("VERGEN_BUILD_TIMESTAMP").and_then(|s| s.parse().ok());

        BuildInfo {
            crate_name: pkg_name,
            crate_version: pkg_ver,
            version: human,
            crate_url,
            git: GitInfo {
                describe,
                branch,
                sha,
                dirty,
            },
            rustc_semver: option_env!("VERGEN_RUSTC_SEMVER"),
            target_triple: option_env!("VERGEN_CARGO_TARGET_TRIPLE"),
            profile: option_env!("VERGEN_CARGO_PROFILE"),
            build_unix,
        }
    })
}

pub fn format_human_version(pkg_ver: &str, git_describe_input: &str, git_dirty: bool) -> String {
    // Some describe configs include "-dirty" in the string; we rely on GIT_DIRTY instead.
    let mut git_describe = git_describe_input;
    let had_dirty_suffix = git_describe.ends_with("-dirty");
    if had_dirty_suffix {
        git_describe = &git_describe[..git_describe.len() - "-dirty".len()];
    }
    let dirty = if git_dirty { "-dirty" } else { "" };

    // Helper: is this a hex-ish commit-ish thing (with optional 'g' prefix)
    fn looks_like_sha(s: &str) -> bool {
        let s = s.strip_prefix('g').unwrap_or(s);
        s.len() >= 7 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    // Case 1: try to parse "...-{distance}-{sha}" from the END, allowing hyphens in the tag
    let parts: Vec<&str> = git_describe.split('-').collect();
    if parts.len() >= 3 {
        let maybe_dist = parts[parts.len() - 2];
        let maybe_sha = parts[parts.len() - 1];

        if maybe_dist.parse::<u64>().is_ok() && looks_like_sha(maybe_sha) {
            // Rejoin everything before the last two parts as the tag (preserves hyphens in tag)
            let tag = parts[..parts.len() - 2].join("-");
            let short = maybe_sha.strip_prefix('g').unwrap_or(maybe_sha);
            return format!("{tag}+{maybe_dist}.g{short}{dirty}");
        }
    }

    // Case 2: bare SHA (no tag)
    if looks_like_sha(git_describe) {
        let short = git_describe.strip_prefix('g').unwrap_or(git_describe);
        return format!("0.0.0+g{short}{dirty}");
    }

    // Case 3: exact tag (possibly with prerelease/build metadata, which may include hyphens)
    // Optional: normalize the tag to your Cargo version if they match ignoring leading 'v'
    // (purely cosmetic; comment out if you want the tag verbatim)
    let tag_ign_v = git_describe.trim_start_matches('v');
    if tag_ign_v == pkg_ver {
        // Prefer showing the 'v' form for aesthetics; drop the 'v' if you don't like it.
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
