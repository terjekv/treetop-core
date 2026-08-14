# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Move the canonical source repository and trusted release identity to the
  `treetop-policy-engine` GitHub organization. The crate name and Rust API are unchanged.

### Added

- Added borrowed `EvaluationObservation` metrics with structured action ID and namespace access, combined total and phase timings, and lazy matched-policy iteration. Existing `MetricsSink` implementations remain source-compatible through the owned `EvaluationStats` adapter.

### Performance

- Allocation-conscious metrics sinks can avoid formatting an owned Cedar action ID and collecting a matched-policy `Vec<String>` on every evaluation. Added end-to-end Callgrind coverage for disabled, legacy, and borrowed sink paths.

## [0.0.19] - 2026-08-11

### Security

- Derived regex labels now replace caller-provided output attributes, and the canonical resource `id` attribute can no longer be overwritten by caller input.
- Policy-listing APIs default to permit candidates, exclude forbid-only actions, and expose whether unevaluated `when` or `unless` clauses are present. Listings remain non-authoritative; callers must use `PolicyEngine::evaluate` before granting access.
- Entity parsing now uses Cedar's typed identifiers, preserves resource namespaces, escapes IDs correctly, and rejects malformed or empty values.
- Cedar entity-conversion internals are no longer publicly exposed, preventing grouped principals from being converted without their authorization-relevant parent relationships.
- Observability no longer records raw principal IDs, uses bounded example metrics, and isolates sink panics from authorization and reload results. Action IDs remain available for consumers with a controlled, bounded action vocabulary.
- Updated the vulnerable `crossbeam-epoch` dependency and migrated the renamed IAI-Callgrind benchmark crate to Gungraun; `cargo audit --deny warnings` is enforced in CI.
- Pinned third-party GitHub Actions and reusable workflows to commit SHAs. The performance workflow retains narrowly scoped pull-request write access for its sticky benchmark report.

### Performance

- Removed redundant `Arc` layers around policy snapshots, avoided cloning resources when no label registry is configured, and eliminated repeated UID/context construction.
- Permit-policy literals and JSON are reference-counted so allow decisions no longer deep-clone precomputed policy metadata.
- Evaluation phase timings no longer double-count group resolution, and disabled metrics avoid policy-ID allocation.
- Request preparation now moves owned Cedar inputs, preallocates and moves group parent sets, and skips resource cloning when no configured labeler applies. Policy listings and metrics dispatch also avoid redundant policy, ID, action, and sink-reference clones.

### Changed

- **BREAKING**: Raised the minimum supported Rust version from 1.89 to 1.93.1 to support current dependency releases, including `serial_test` 4.0.1.
- **BREAKING**: `EvaluationStats` no longer contains `principal_id`; `action_id` remains available for bounded consumer metrics.
- **BREAKING**: `PermitPolicy` and `PolicyVersion` metadata fields now use `Arc`-backed values while preserving their serialized and OpenAPI shapes.
- **BREAKING**: `FromDecisionWithPolicy::from_decision_with_policy` now returns `Result` instead of panicking when an allow result has no permit metadata.
- **BREAKING**: Removed unused `PolicyError` lock and qualified-ID variants and marked the enum `#[non_exhaustive]`.
- **BREAKING**: Default policy listings and `PolicyEffectFilter::default()` now select permit policies instead of all effects.
- Serialized `UserPolicies` now includes `has_non_scope_constraints` so non-Rust consumers can detect unevaluated conditions.
- Upgraded and exactly pinned Cedar to 4.12.0 so build metadata identifies the version actually linked, removed unused runtime dependencies, and moved test-only dependencies to development dependencies.
- Build timestamps are emitted only from `SOURCE_DATE_EPOCH`; builds no longer embed the current wall-clock time. Build metadata also supports Cargo-normalized package manifests, refreshes when Git refs, the index, tags, or tracked worktree inputs change, and avoids nonexistent Git watch paths that defeat incremental builds.
- Migrated the instruction-level benchmark suite to Gungraun 0.19.4 and the canonical Gungraun inputs in version 3 of the reusable performance workflow, while preserving benchmark target names for base/head history compatibility.
- Restricted crate packaging to an explicit allowlist and expanded strict formatting, lint, test, documentation, snapshot, audit, and package checks in CI.

## [0.0.18] - 2026-07-04

### Changed

- Bumped `cedar-policy` and `cedar-policy-core` dependencies to version 4.11.2.
- Updated Cargo dependencies to their latest Rust 1.96-compatible versions.
- Updated `vergen` and `vergen-gitcl` build dependencies to version 10 and migrated `build.rs` to the new builder API.

## [0.0.17] - 2026-04-04

### Added

- **Request Context Support**:
  - `RequestContext` struct for passing arbitrary key-value context attributes to Cedar evaluation, merged with resource context at evaluation time
  - `PolicyEngine::evaluate_with_context()` to evaluate with explicit request context
  - `PolicyEngine::evaluate_with_context_and_diagnostics()` to evaluate with both context and diagnostics
- **Decision Diagnostics**:
  - `DecisionDiagnostics` struct wrapping `Decision` with deny-side forbid policy IDs (`matched_forbid_policy_ids`)
  - `PolicyEngine::evaluate_with_diagnostics()` to include matched forbid policy IDs on deny decisions
  - Forbid policy IDs are now precomputed at load time for efficient diagnostics
- **Schema-Validated Engine Construction**:
  - `PolicyEngine::new_from_str_with_schema()` to create an engine with schema-based policy and request validation
  - `PolicyEngine::new_from_str_with_cedarschema()` to create an engine from policy text and Cedar schema text
- Cedar schema support now documents and supports schema replacement during reload via:
  - `PolicyEngine::reload_from_str_with_schema(...)`
  - `PolicyEngine::reload_from_str_with_cedarschema(...)`
- **Action Matching in Policy Listings**:
  - `list_policies()` and `list_policies_with_effect()` now match action constraints in addition to principal and resource constraints
- **New Public Exports**:
  - `RequestContext`, `DecisionDiagnostics`, `compile_policy_with_schema`, and `Schema` (re-exported from `cedar_policy`)
- Expanded schema/reload test coverage:
  - Reload failure atomicity tests (snapshot/version/behavior unchanged on failed reload)
  - Non-schema engine -> schema-enabled reload transition test

### Changed

- `PolicyReload` tracing remains at `debug` level, with schema-status fields:
  - `schema_enabled`
  - `schema_reloaded`
  - `schema_previously_enabled` (schema-replacing reloads)
- Engine unit tests were refactored out of `src/engine.rs` into `src/engine/tests/*` and split by domain for maintainability (`core`, `evaluate`, `listing`, `reload`, `schema`).
- Bumped `cedar-policy` and `cedar-policy-core` dependencies to version 4.9.0.
- Bumped `sha2` from 0.10 to 0.11.

## [0.0.16] - 2026-02-09

### Added

- **Policy Matching & Querying**:
  - `PolicyMatchReason` enum to explain why policies matched (PrincipalEq, PrincipalIn, PrincipalAny, PrincipalIs, PrincipalIsIn, ResourceEq, ResourceIn, ResourceAny, ResourceIs, ResourceIsIn)
  - `PolicyMatch` struct containing Cedar policy ID and match reasons
  - `PolicyEffectFilter` enum (Any, Permit, Forbid) for filtering policies by effect
  - `UserPolicies::matches()` method to access match metadata
  - `UserPolicies::reasons_for_policy()` method to get reasons for a specific policy
  - Multiple new policy listing methods on `PolicyEngine`:
    - `list_policies()` - List policies for a concrete request
    - `list_policies_with_effect()` - List policies with effect filtering
    - `list_policies_for_user_with_resource()` - Combine principal and resource constraints
    - `list_policies_for_user_with_resource_and_effect()` - With both resource and effect filters
    - `list_policies_for_group()` - For group principals
    - `list_policies_for_group_with_resource()` - For groups with resource filtering
  - Public utility functions: `action_entity_uid()`, `group_entity_uid()`, `resource_entity_uid()`, `user_entity_uid()`, `namespace_segments()`
- **Performance Tracking & Benchmarking**:
  - Comprehensive iai-callgrind benchmarks for instruction-level performance analysis
  - Benchmark suites for baseline scenarios, groups, labels, namespaced operations, and internal operations
  - `bench-internal` feature flag to expose internal helpers for benchmarking
  - `docs/Perf.md` documentation for performance tracking
  - `scripts/perf/compare_criterion.py` for performance analysis
  - CI workflow for automated performance tracking
- **Dependency Management**:
  - Configured Dependabot for automated Cargo dependency updates

### Changed

- `UserPolicies` now includes match metadata with reasons explaining why each policy matched
- `UserPolicies` results are now deterministically sorted by Cedar policy ID
- `UserPolicies` serialization now includes a `matches` field with match metadata

### Performance

- Cached static `Authorizer` instance (stateless, reusable across all evaluations)
- Reduced redundant UID conversions in Cedar request building by pre-converting UIDs once
- Optimized group UID collection with pre-allocation to reduce memory overhead
- Added inline annotations to hot-path functions for improved performance
- Label application now only clones resources when a label registry is configured

## [0.0.15] - 2026-02-02

### Added

- `matched_policies` in `EvaluationStats` to capture matched permit policy IDs
- `serial_test` dev dependency for serializing metrics-related tests

### Changed

- **BREAKING**: `list_policies_for_user()` signature changed to accept `groups` and `namespace` parameters
  - Old: `list_policies_for_user(user, namespace)`
  - New: `list_policies_for_user(user, groups, namespace)`
- Prometheus sink example updated for the new `matched_policies` field
- Metrics integration tests made serial (including DNS test evaluations) to avoid global sink interference

## [0.0.14] - 2026-02-01

### Changed

- **BREAKING**: `PermitPolicy` now has two new fields (`annotation_id` and `cedar_id`)
  - Removed private field accessors; access fields directly instead of via `policy.literal()` → `policy.literal` and so on
- **BREAKING**: `PermitPolicy::new()` signature changed to require `cedar_id` parameter
  - Old: `new(literal, json)`
  - New: `new(literal, json, cedar_id)` (cedar_id always comes from Cedar's PolicySet)
- Logs now include `policy_id` (either annotation_id or cedar_id) when logging the matched policy during evaluation, instead of the complete policy content, making logs much more concise

### Added

- Policy metadata precomputation at load time for improved hot-path performance
  - `annotation_id` (from `@id` annotation or JSON annotations.id field) now precomputed on policy load
  - `cedar_id` (from Cedar's internal PolicyId) stored directly in `PermitPolicy`
  - Eliminates per-request policy serialization overhead
  - `annotation_id` is `Option<String>`, while `cedar_id` is always `String`
  - Use `permit_policy.id()` to get the best available ID as `&str`

## [0.0.13] - 2026-18-01

### Added

- Metrics & Observability (feature `observability`):
  - `MetricsSink` trait to collect `EvaluationStats` and `ReloadStats`
  - Per-phase timing for labels, entities, groups, authorize
  - Examples for Prometheus and OpenTelemetry tracing
  - See [docs/Metrics.md](docs/Metrics.md) for details

- `LabelRegistry` struct for managing resource labelers with per-engine ownership
- `LabelRegistryBuilder` with typestate pattern for safe progressive labeler initialization
- `PolicyEngine::with_label_registry()` method to configure labels at engine creation
- `PolicyEngine::set_label_registry()` method to update labels on existing engines
- `PolicyEngine::label_registry()` method to access the configured label registry
- Enhanced error handling with better context propagation
- `CedarType` enum centralizing Cedar entity type names (User, Action, Group, Resource, Principal)
- Comprehensive test coverage improvements:
  - Concurrency and thread-safety tests
  - Error handling and context validation tests
  - FromStr implementation tests with edge cases
  - Label registry behavior tests
  - Metrics and observability tests across types

### Changed

- **BREAKING**: Label registry moved from global static to per-engine instance
  - Global `init_label_registry()` and `apply_labels()` functions removed.
  - Users must migrate to `LabelRegistryBuilder` with `PolicyEngine::with_label_registry()`
- **BREAKING**: Labeling now happens per-engine rather than globally
  - Each `PolicyEngine` instance can have its own configured labels
  - Label application during evaluation uses the engine's registry if configured
- **BREAKING**: `UserPolicies::actions()` now returns `&[EntityUid]` instead of `Vec<EntityUid>`
  - Eliminates unnecessary cloning on every call; callers can use `.to_vec()` if ownership is needed
- **BREAKING**: `Groups` now implements `IntoIterator` instead of `Iterator`
  - Previous `Iterator` implementation was destructive (consumed via `pop()`)
  - Use `.into_iter()` for owned iteration or `&groups` for borrowed iteration
- **BREAKING**: Removed `From<T>` trait implementation for `Action`
  - Previously silently created actions on parse failure using fallback behavior
  - Use `Action::new(id, namespace)` explicitly or `Action::from_str()` for parsing
  - Ensures parse errors are visible to callers rather than swallowed
- Replaced `once_cell` dependency with standard library `OnceLock`
- Improved error context with detailed Cedar error information
- Magic strings replaced with `CedarType` enum throughout codebase
- `PolicyEngine::Clone` is preserved for backward compatibility; use `Arc<PolicyEngine>` for idiomatic thread sharing
- CI now builds, tests, and runs clippy with `--all-features`, and rejects unreferenced snapshots
- CI cargo-insta installation now uses `taiki-e/install-action@v2` for better caching and faster builds
- Internal test infrastructure optimized with lock-free atomic counters for metrics collection
- `EvaluationPhases::overhead_ms()` now guarantees non-negative values using `max(0.0, ...)` to handle timing precision edge cases

### Migration Guide

**Old API** (no longer supported):

```rust
// Initialize global registry once
init_label_registry(vec![
    Arc::new(labeler1),
    Arc::new(labeler2),
]);

let engine = PolicyEngine::new_from_str(policies)?;
let decision = engine.evaluate(&request);
```

**New API** (with single or multiple labelers):

```rust
use std::sync::Arc;

// Single labeler
let engine = PolicyEngine::new_from_str(policies)?
    .with_label_registry(
        LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler))
            .build()
    );

let decision = engine.evaluate(&request);
```

Or with multiple labelers:

```rust
let mut builder = LabelRegistryBuilder::new();
for labeler in vec![labeler1, labeler2, labeler3] {
    builder = builder.add_labeler(Arc::new(labeler));
}

let engine = PolicyEngine::new_from_str(policies)?
    .with_label_registry(builder.build());

let decision = engine.evaluate(&request);
```

## [0.0.12] - 2025-12-04

### Added

- Policy snapshoting and version tracking
  - A new `PolicyVersion` struct represents the version of the policies, with the following fields:
    - `hash`: SHA-256 hash of the policy text
    - `loaded_at`: ISO 8601 timestamp of when the policy was loaded
  - A new `PolicySnapshot` struct represents a snapshot of the currently loaded policies, with the following methods:
    - `policy_set()`: Returns a reference to the current `cedar::PolicySet`
    - `version()`: Returns a `PolicyVersion` struct representing the version of the policies in this snapshot.
  - PolicyEngine now offers `current_snapshot()` and `current_version()` methods.
  - `current_snapshot()` returns the `PolicySnapshot` for the currently loaded policies.
  - `current_version()` returns a `PolicyVersion` for the currently loaded policies.
- `Decision` enum variants now include a `version` field containing a `PolicyVersion`.
- Lock-free policy reloading using `arc-swap` for better concurrency
- Evaluation timing metrics in debug logs

### Changed

- **BREAKING**: `Decision::Allow` now includes `version` field: `Decision::Allow { policy, version }`
- **BREAKING**: `Decision::Deny` now includes `version` field: `Decision::Deny { version }`
- Internal policy storage changed from `RwLock<PolicySet>` to `ArcSwap<Snapshot>` for lock-free reads
- `PolicyEngine` is now fully thread-safe with non-blocking reads during evaluation

## [0.0.11] - 2025-09-01

### Added

- Increased testing

### Changed

- **BREAKING**: Flattened the qualified ID structures in serialization (ie, going from `{"id" : { "id": "foo"}}` to `{"id": "foo"}`).

## [0.0.10] - 2025-08-21

### Added

- The version of the `cedar` library used is now found in the `BuildInfo` struct.

### Fixed

- Fixed build information when delivered as a crate.

## [0.0.9] - 2025-08-21

### Added

- Build information, exposing a `build_info()` function that returns a `&'static BuildInfo` instance.

## [0.0.8] - 2025-08-19

### Added

- Fully generic support for resource types and their internals.
- Fully generic support for labels on fields in resources.

## [0.0.7] - 2025-07-05

### Added

- [utoipa](https://docs.rs/utoipa/latest/utoipa/) [ToSchema](https://docs.rs/utoipa/latest/utoipa/derive.ToSchema.html) support for types that are exported from the crate, such as `Request` and all the types it itself uses. This allows consumer libraries to use these types directly in their API, as they are already serializable, and now also get OpenAPI documentation via Utoipa.

## 0.0.6 - 2025-07-04

### Added

- Proper namespace support.
- Add `from_str` for `Action`, `Group`, and `User` to allow the creation from strings. For `Group` and `Action` the format is the canonical form, e.g. `<Namespaces::>Group::"group_name"` and `<Namespaces::>Action::"action_name"`, while for `User` you may also add unquoted groups bracketed by `[]` and seperated by comma (`,`) at the end, e.g. `User::"alice"[admins,users]`. For all input, quoting of the identity element is optional, so you may also use `User::alice`, `Group::admins`, or `DNS::Action::create_host`.

### Changed

- Updated Cedar to version [4.5](https://github.com/cedar-policy/cedar/releases/tag/v4.5.0). From a consumer perspective, the major change is support for [trailing commas](https://github.com/cedar-policy/rfcs/blob/main/text/0071-trailing-commas.md) in Cedar policies.

## 0.0.5 - 2025-06-28

### Added

- Group support. Group principals are `Group::<Namespace::>"group_name"`, and you can use the `in` operator to match its group members. Note that using `==` will only match the group itself, not its members. Also see the readme for more details on how to use groups.

## 0.0.4 - 2025-06-27

### Changed

- `Decision::Allow` responses now include a `PermitPolicy`, which contains the policy that was matched, with two fields:
  - `literal`: The literal representation of the policy that was matched, in Cedar syntax.
  - `json`: The JSON representation of the policy that was matched.

## 0.0.3 - 2025-06-25

### Added

- Support for generic resources. Passing `Resource::Generic { kind: "House".into(), id: "house-1".into() }` to a request will match policies that use `resource is House` and its `id` property will be `"house-1"`. See the readme for more details on how to use generic resources.
