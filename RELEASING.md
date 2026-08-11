# Releasing

Releases are published to crates.io by `.github/workflows/release.yml` when a
tag named `vX.Y.Z` is pushed. The tag must match the version in `Cargo.toml`,
and its commit must be on `main`.

crates.io Trusted Publishing is configured for this repository's `release.yml`
workflow and its `release` environment. The workflow uses GitHub OIDC to obtain
a short-lived publishing token; no crates.io API token or GitHub Actions secret
is needed.

## Publishing a version

1. Update the version in `Cargo.toml` and regenerate `Cargo.lock` if needed.
2. Add the dated release entry to `Changelog.md`.
3. Merge the release commit into `main` and wait for the Rust workflow to pass.
4. Tag that commit and push the tag:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

The release workflow checks formatting, strict all-target Clippy, tests,
documentation, Markdown, snapshots, dependency advisories, and the packaged
crate before publishing. Rerunning it is safe when that exact version is
already on crates.io.
