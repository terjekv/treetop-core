use vergen::{Build, Cargo, Emitter, Rustc};
use vergen_gitcl::Gitcl;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let git = Gitcl::builder()
        .describe(true, true, None)
        .sha(true)
        .branch(true)
        .dirty(true)
        .build();
    let cargo = Cargo::builder()
        .dependencies(true)
        .features(true)
        .target_triple(true)
        .build();

    let rustc = Rustc::builder()
        .host_triple(true)
        .semver(true)
        .build();
    let build = Build::builder()
        .build_date(true)
        .build_timestamp(true)
        .build();

    Emitter::default()
        .add_instructions(&git)?
        .add_instructions(&cargo)?
        .add_instructions(&rustc)?
        .add_instructions(&build)?
        .emit()?;

    Ok(())
}
