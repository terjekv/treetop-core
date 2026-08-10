use std::path::Path;
use std::process::Command;

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn emit_optional(name: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        println!("cargo:rustc-env={name}={value}");
    }
}

fn cedar_version(manifest_dir: &str) -> Option<String> {
    let manifest = std::fs::read_to_string(Path::new(manifest_dir).join("Cargo.toml")).ok()?;
    let dependency = manifest
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("cedar-policy ="))?;
    let version = dependency.split_once('=')?.1.trim().trim_matches('"');
    Some(version.trim_start_matches(['=', '^', '~']).to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    if let Some(git_head) = command_output("git", &["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={git_head}");
    }

    emit_optional(
        "TREETOP_GIT_DESCRIBE",
        command_output("git", &["describe", "--tags", "--always", "--dirty"]),
    );
    emit_optional(
        "TREETOP_GIT_SHA",
        command_output("git", &["rev-parse", "HEAD"]),
    );
    emit_optional(
        "TREETOP_GIT_BRANCH",
        command_output("git", &["branch", "--show-current"]),
    );
    let dirty = command_output("git", &["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|output| !output.is_empty());
    println!("cargo:rustc-env=TREETOP_GIT_DIRTY={dirty}");

    emit_optional(
        "TREETOP_RUSTC_SEMVER",
        std::env::var("RUSTC")
            .ok()
            .and_then(|rustc| command_output(&rustc, &["--version"]))
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
