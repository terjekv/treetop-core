mod build_support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use build_support::cedar_policy_version;

fn command_output(cwd: &Path, program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_output(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    // A packaged crate can be built below the source repository's `target/`
    // directory. Do not accidentally discover that parent repository and
    // embed unrelated checkout state in the package build.
    if manifest_dir.join(".cargo_vcs_info.json").is_file() {
        return None;
    }
    command_output(manifest_dir, "git", args)
}

fn emit_optional(name: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        println!("cargo:rustc-env={name}={value}");
    }
}

fn cedar_version(manifest_dir: &Path) -> Option<String> {
    let manifest = std::fs::read_to_string(manifest_dir.join("Cargo.toml")).ok()?;
    cedar_policy_version(&manifest)
}

fn absolute_git_path(manifest_dir: &Path, git_path: &str) -> Option<PathBuf> {
    git_output(
        manifest_dir,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            git_path,
        ],
    )
    .map(PathBuf::from)
}

fn insert_existing(paths: &mut BTreeSet<PathBuf>, path: Option<PathBuf>) {
    if let Some(path) = path.filter(|path| path.exists()) {
        paths.insert(path);
    }
}

fn git_watch_paths(manifest_dir: &Path) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    if git_output(manifest_dir, &["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true")
    {
        return paths;
    }

    // HEAD changes for detached checkouts; the resolved ref changes for an
    // ordinary commit on a branch. The index and tracked worktree files drive
    // the dirty flag, while tag and packed-ref changes affect `git describe`.
    // Git resolves paths that do not exist yet; do not emit those because Cargo
    // would treat a missing rerun target as perpetually changed.
    for git_path in ["HEAD", "index", "packed-refs", "refs/heads", "refs/tags"] {
        insert_existing(&mut paths, absolute_git_path(manifest_dir, git_path));
    }

    if let Some(symbolic_ref) = git_output(manifest_dir, &["symbolic-ref", "--quiet", "HEAD"]) {
        insert_existing(&mut paths, absolute_git_path(manifest_dir, &symbolic_ref));
    }

    if let Some(files) = git_output(manifest_dir, &["ls-files", "-z"]) {
        paths.extend(
            files
                .split('\0')
                .filter(|file| !file.is_empty())
                .map(|file| manifest_dir.join(file))
                .filter(|path| path.exists()),
        );
    }

    paths
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);

    for path in ["Cargo.toml", "build.rs", "build_support.rs"] {
        println!("cargo:rerun-if-changed={path}");
    }
    for variable in [
        "SOURCE_DATE_EPOCH",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    for path in git_watch_paths(&manifest_dir) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    emit_optional(
        "TREETOP_GIT_DESCRIBE",
        git_output(
            &manifest_dir,
            &["describe", "--tags", "--always", "--dirty"],
        ),
    );
    emit_optional(
        "TREETOP_GIT_SHA",
        git_output(&manifest_dir, &["rev-parse", "HEAD"]),
    );
    emit_optional(
        "TREETOP_GIT_BRANCH",
        git_output(&manifest_dir, &["branch", "--show-current"]),
    );
    let dirty = git_output(
        &manifest_dir,
        &["status", "--porcelain", "--untracked-files=no"],
    )
    .is_some_and(|output| !output.is_empty());
    println!("cargo:rustc-env=TREETOP_GIT_DIRTY={dirty}");

    emit_optional(
        "TREETOP_RUSTC_SEMVER",
        std::env::var("RUSTC")
            .ok()
            .and_then(|rustc| command_output(&manifest_dir, &rustc, &["--version"]))
            .and_then(|version| version.split_whitespace().nth(1).map(str::to_string)),
    );
    emit_optional("TREETOP_TARGET_TRIPLE", std::env::var("TARGET").ok());
    emit_optional("TREETOP_PROFILE", std::env::var("PROFILE").ok());
    emit_optional("TREETOP_CEDAR_VERSION", cedar_version(&manifest_dir));

    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        let epoch = epoch.parse::<i64>().map_err(|error| {
            format!("SOURCE_DATE_EPOCH must be a non-negative Unix timestamp: {error}")
        })?;
        if epoch < 0 {
            return Err("SOURCE_DATE_EPOCH must be a non-negative Unix timestamp".into());
        }
        println!("cargo:rustc-env=TREETOP_BUILD_UNIX={epoch}");
    }

    Ok(())
}
