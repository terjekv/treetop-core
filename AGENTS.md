# Repository Guidelines

## Project Overview

`treetop-core` is a Rust library that turns Cedar policies and application-owned
request data into authorization decisions. Treat authorization behavior, public
Rust types, serialized shapes, and policy diagnostics as security-sensitive API
surface.

The crate supports optional Cedar schema validation, atomic policy and labeler
reloads, candidate-policy listing, observability sinks, snapshots, Criterion
benchmarks, and Gungraun/Callgrind benchmarks.

## Verification

- Run formatting with `cargo fmt --all --check`.
- Run strict linting across every target and feature combination with
  `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- Run the full test and doctest suite with
  `cargo test --locked --all-features`.
- When snapshots are affected, install `cargo-insta` and run
  `cargo insta test --all-features --unreferenced reject -- -q`. Review changed
  snapshots; do not accept them blindly.
- Check documentation with
  `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`.
- Lint Markdown with
  `npx markdownlint-cli2 --config .markdownlint.json "**/*.md" "!target"`.
- Audit locked dependencies with `cargo audit`. Investigate transitive and
  development-only findings instead of suppressing them without a written
  rationale.
- For manifest, release, or package-boundary changes, inspect the exact crate
  contents with `cargo package --locked --list` and finish with
  `cargo publish --locked --dry-run`.
- Prefer the full suite once more than a few targeted tests are relevant. Use a
  targeted test while iterating, then run the full checks before completion.

## Architecture

- `src/engine.rs` owns the authorization hot path. A compiled `PolicySnapshot`
  is immutable and replaced atomically through `ArcSwap`; one evaluation must
  use one snapshot from request preparation through its returned version.
- `src/loader.rs` parses and schema-validates policies and precomputes metadata.
  Build a complete replacement snapshot before publishing it.
- `src/types/` contains the public request, identity, context, decision, and
  policy-listing types. Serde and Utoipa representations are public API.
- `src/labels.rs` derives server-controlled resource attributes. Labelers run in
  insertion order and are part of the authorization trust boundary.
- `src/query.rs` and `src/policy_match.rs` perform structural matching for
  policy-listing APIs. They do not execute Cedar conditions.
- `src/metrics.rs` is feature-gated observability infrastructure. Sink callbacks
  execute synchronously in the evaluation path.
- `benches/` and `docs/Perf.md` define the performance baseline. Keep benchmark
  declarations in `Cargo.toml` and the matrix in `.github/workflows/perf.yml` in
  sync.
- `build.rs` and `src/build_info.rs` provide build metadata. Keep builds
  deterministic where possible and avoid adding build-time work casually.

## Authorization And Security Invariants

- `PolicyEngine::evaluate*` is the authorization source of truth. Policy-listing
  methods only match static principal, action, resource, and effect constraints;
  they do not evaluate `when` or `unless` clauses, and an `Any` effect filter can
  include forbids. Never use `UserPolicies`, `actions()`, or listing results as
  proof that an operation is allowed.
- Fail closed. Callers must not turn `PolicyError`, parse failures, schema
  failures, missing data, or observability failures into an allow decision.
- Preserve schema validation across normal reloads. Policy and schema
  replacements must validate fully before the atomic swap; a failed reload must
  leave the prior snapshot active.
- Treat principal identities, group membership, resource attributes, and request
  context as trusted application inputs. Do not pass client-asserted group
  membership or derived authorization labels through unchecked.
- A labeler's output must not be forgeable through preexisting untrusted
  attributes. Define whether an output is replaced or merged, make that choice
  explicit, and test empty, conflicting, and repeated applications.
- Prefer Cedar's typed parsers and validating constructors over hand-built
  entity strings. Reject malformed or empty IDs, invalid namespaces, malformed
  group suffixes, invalid IP values, and schema-incompatible attributes at the
  boundary.
- Keep evaluation code panic-free. Return a specific `PolicyError` for malformed
  or adversarial inputs; reserve `unwrap`, `expect`, and `panic!` for tests and
  provable build-time invariants.
- Do not log full policy text, context, resource attributes, or other secrets.
  Principal and resource identifiers may be personal or sensitive data; redact
  or hash them where appropriate.
- Metrics labels must have bounded cardinality and valid backend escaping. Raw
  user IDs, resource IDs, or attacker-controlled policy annotations are unsafe
  default labels.
- Expose forbid diagnostics only where the caller is allowed to learn policy
  structure. Diagnostics explain a decision; they must never change it.

## Performance

- Treat `PolicyEngine::prepare`, entity construction, authorization, decision
  construction, and metrics dispatch as hot paths.
- Avoid reparsing entity UIDs, cloning a complete `Resource`, allocating
  temporary collections, or deep-cloning policy JSON and literals per
  evaluation unless a benchmark demonstrates the tradeoff is acceptable.
- Keep snapshots immutable and reads lock-free. Do not introduce a global mutex,
  blocking I/O, or policy compilation into evaluation.
- Labelers should be fast, deterministic, side-effect-free except for their
  provided resource, and idempotent. Compile regular expressions and other
  matchers once, outside evaluation.
- Metrics sinks run synchronously. They must not block, perform network I/O, or
  retain an unbounded event history. Prefer atomics, bounded channels, and
  fixed-cardinality aggregates.
- Phase measurements must be non-overlapping if they are summed. If phases are
  nested, document that fact and do not double-count them as overhead.
- Add focused Criterion benchmarks for wall-clock trends and Gungraun
  benchmarks for deterministic instruction-level trends. Keep benchmark
  fixtures stable and representative of production request shapes. The legacy
  `iai` Cargo target names are intentional: v3 uses them to pair historical
  IAI-Callgrind results with Gungraun results.
- For a performance-sensitive change, compare the relevant baseline and feature
  sets described in `docs/Perf.md`; do not infer improvement from code shape
  alone.

## Rust And Public API Standards

- Follow idiomatic Rust and let `rustfmt` own formatting. Prefer clear code over
  clever iterator chains in security-sensitive paths.
- Keep invalid states out of public types where practical. Use private fields,
  validating constructors, and explicit accessors; use `Result` when validation
  can fail.
- Be deliberate about SemVer. Adding a variant to an exhaustively matchable
  public enum is breaking unless the type is already `#[non_exhaustive]`.
- Keep public errors actionable and preserve their source when practical. Remove
  obsolete lock/error variants only as an intentional API change.
- Public types and methods need useful rustdoc, including security semantics and
  error behavior. Update doctests when examples change.
- Keep Serde and Utoipa definitions aligned. Snapshot intentional JSON changes
  and call them out as API changes.
- Prefer standard-library operations over a new dependency for small tasks. Put
  test-only tooling in `[dev-dependencies]`, remove unused direct dependencies,
  and explain new runtime or build dependencies.
- Use `#[cfg(test)]` for test modules and feature gates for optional runtime
  behavior. Check default features as well as `--all-features` when changing
  conditional compilation.
- Avoid broad `#[allow(...)]` attributes. Scope a necessary exception narrowly
  and explain the invariant that makes it safe.

## Tests And Snapshots

- Add regression tests for every authorization bug. Include the expected allow,
  deny, or error outcome and the relevant diagnostics/version behavior.
- Cover permit and forbid precedence, groups, namespaces, request context,
  schema validation, failed reload rollback, and concurrent reload/evaluation
  behavior when those paths change.
- For parsing changes, test malformed delimiters, quotes, escapes, empty values,
  namespaced resources, and round trips through Cedar and Serde.
- Keep each test focused on one behavior. Parameterize input variants when the
  assertion is the same.
- Snapshot tests supplement semantic assertions; they do not replace them.
  Review snapshots for accidental policy text, IDs, timestamps, or unstable
  ordering.
- Tests share global tracing and metrics state in places. Use existing serial
  test patterns when mutating a global sink or subscriber, and always restore or
  replace global state deterministically.

## Observability

- The `observability` feature must not change an authorization decision.
- Keep the disabled feature path cheap and ensure the enabled path is measured.
- Dispatch one evaluation event consistently to one sink snapshot. Avoid loading
  a replaceable global sink separately for logically related callbacks.
- Bound, redact, and escape exported dimensions. Examples must demonstrate
  production-safe cardinality and memory behavior rather than only small test
  inputs.
- Keep timing field names and units stable. Update `docs/Metrics.md`, examples,
  integration tests, and benchmarks together when the contract changes.

## Dependencies, CI, And Releases

- Keep `Cargo.lock` committed and use `--locked` in CI and release verification.
- Configure Dependabot for both Cargo and GitHub Actions. Review dependency
  updates for MSRV, feature, license, security, compile-time, and binary-size
  impact.
- Pin third-party GitHub Actions and reusable workflows to reviewed commit SHAs.
  Keep workflow permissions minimal, especially for pull-request jobs.
- CI must enforce formatting, strict all-target Clippy, all-feature tests,
  snapshot hygiene, documentation, and dependency auditing rather than merely
  printing warnings.
- Keep the packaged crate intentionally small with `include` or `exclude` rules.
  Never publish editor settings, agent settings, secrets, CI-only fixtures, or
  benchmark artifacts accidentally.
- Follow `RELEASING.md`: update `Cargo.toml` and `Cargo.lock`, add a dated entry to
  `Changelog.md`, merge to `main`, then tag that exact commit as `vX.Y.Z`.
- Treat the changelog review as required for every user-visible behavior,
  security, performance, public API, or serialized-shape change. Explicitly
  document breaking changes and caller migration steps.

## Change Discipline

- Merge pull requests into `main` with a squash merge rather than a merge commit
  or rebase merge.
- Use the detailed pull request description as the squash commit body. Preserve
  its substantive summary, rationale, behavior notes, breaking-change and
  migration guidance, and issue references, but remove verification-only
  sections such as test commands and checklists before merging.
- Keep edits scoped and preserve unrelated user changes in a dirty worktree.
- Read the surrounding implementation, tests, docs, and benchmarks before
  changing authorization behavior.
- Add or update tests with behavior changes. Add a benchmark when a hot-path
  regression would otherwise be easy to miss.
- Do not weaken checks, delete snapshots, suppress advisories, or widen trust
  boundaries merely to make CI pass.
- Record assumptions and unresolved security or performance tradeoffs in the
  change description so reviewers can evaluate them explicitly.
