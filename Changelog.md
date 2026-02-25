# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cedar schema support now documents and supports schema replacement during reload via:
  - `PolicyEngine::reload_from_str_with_schema(...)`
  - `PolicyEngine::reload_from_str_with_cedarschema(...)`
- Expanded schema/reload test coverage:
  - Reload failure atomicity tests (snapshot/version/behavior unchanged on failed reload)
  - Non-schema engine -> schema-enabled reload transition test

### Changed

- `PolicyReload` tracing remains at `debug` level, with schema-status fields:
  - `schema_enabled`
  - `schema_reloaded`
  - `schema_previously_enabled` (schema-replacing reloads)
- Engine unit tests were refactored out of `src/engine.rs` into `src/engine/tests/*` and split by domain for maintainability (`core`, `evaluate`, `listing`, `reload`, `schema`).

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
