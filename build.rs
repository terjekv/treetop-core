use vergen::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder};
use vergen_gitcl::GitclBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let git = GitclBuilder::default()
        .describe(true, true, None)
        .sha(true)
        .branch(true)
        .dirty(true)
        .build()?;
    let cargo = CargoBuilder::default()
        .dependencies(true)
        .features(true)
        .target_triple(true)
        .build()?;

    let rustc = RustcBuilder::default()
        .host_triple(true)
        .semver(true)
        .build()?;
    let build = BuildBuilder::default()
        .build_date(true)
        .build_timestamp(true)
        .build()?;

    Emitter::default()
        .add_instructions(&git)?
        .add_instructions(&cargo)?
        .add_instructions(&rustc)?
        .add_instructions(&build)?
        .emit()?;

    Ok(())
}
