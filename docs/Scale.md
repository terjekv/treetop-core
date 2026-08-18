# Operating at Large Policy-Set Scale

This document describes the operational consequences of loading tens or hundreds
of thousands of Cedar policies into one `PolicyEngine`. It also records the first
scale baseline and the questions that future performance work must answer.

The scale suite is an exercised envelope, not a production service-level
objective or an unconditional support guarantee. Hardware, allocator behavior,
policy shape, schema complexity, request shape, concurrency, and surrounding
process memory all affect the result. Measure the exact production corpus and
request distribution before setting capacity or latency expectations.

## Exercised Scale Tiers

| Policy count | Automation | Intended meaning |
| ---: | --- | --- |
| 1,000 | Weekly probe and benchmark | Lower point for detecting fixed costs and scaling shape |
| 10,000 | Pull-request correctness; weekly probe and benchmark | Routine regression smoke test, not a production SLO |
| 100,000 | Weekly correctness, probe, and benchmark | Large-set reference envelope and capacity signal |
| 250,000 | Manual dispatch | Exploratory stress point; completion is not a compatibility guarantee |

The scheduled matrix generates policies at runtime. No large generated policy
file is stored in the repository or published crate.

## Consequences and Expectations

### Authorization stays on the request CPU path

`PolicyEngine::evaluate*` performs Cedar authorization synchronously on the
calling thread. The current synthetic corpus shows broadly linear request cost
through 10,000 policies and a larger-than-linear increase at 100,000, where cache
and memory-system effects become more visible. A monolithic 100,000-policy set
should therefore be considered unsuitable for a latency-sensitive request path
unless the production workload demonstrates an acceptable tail-latency and CPU
budget.

Concurrency does not remove this cost. It distributes evaluations across cores
until CPU, memory bandwidth, or cache pressure becomes the limit. Capacity plans
must use concurrent throughput and p95/p99 latency, not the single-request median
alone.

Policy-listing APIs also scan structural constraints. They are faster than full
authorization in the current corpus, but they remain non-authoritative and must
never replace `evaluate*` as proof that an operation is allowed.

### Load and reload are control-plane operations

Parsing, strict schema validation, policy metadata construction, and hashing all
happen synchronously in `new_from_str*` and `reload_from_str*`. Large loads should
run during initialization or on a dedicated control-plane worker, not on a
latency-sensitive request handler. Readiness should be published only after the
initial snapshot has loaded and validated successfully.

Reload builds and validates a complete replacement before the atomic swap.
Concurrent evaluations continue using the previous immutable snapshot and do
not observe a partial policy set. This preserves authorization consistency, but
it also means the process needs enough transient memory for the active and
replacement snapshots at the same time.

Debounce or coalesce frequent updates. Back-to-back reloads can retain additional
snapshot generations when older evaluations still hold their `Arc` references.
The exact number and lifetime depend on request duration and reload cadence.

### Memory is much larger than policy text

A snapshot stores Cedar's compiled `PolicySet` plus Treetop's permit and forbid
metadata. Permit metadata includes the policy literal and JSON representation so
allow decisions can return policy details without serializing on the hot path.
The synthetic corpus is approximately 90% permits, making it intentionally
representative of this memory-sensitive path.

At 100,000 policies, each generated text corpus is only about 15.94 MiB, while
the controlled probe reports roughly 996 MiB of additional resident memory after
the first load. That value includes the live snapshot and allocator-retained
temporary load allocations; it is not a precise heap-size measurement. Atomic
replacement raised the process high-water mark to about 1.72 GiB. The broader
correctness scenario, which also cloned the complete policy list before reload,
peaked around 1.93 GiB.

Dropping the old snapshot does not guarantee that RSS immediately falls. The
allocator can retain freed pages in arenas for later reuse, so container and
process monitors may continue to report a value near the reload high-water mark.
Capacity planning must include this retained RSS, the input strings, application
entities and caches, concurrent requests, observability, and a safety margin.

### Policy shape changes the result

Policy count alone is not a sufficient capacity metric. Important dimensions
include:

- permit/forbid ratio and returned permit metadata;
- literal, annotation, identifier, and JSON size;
- condition complexity and extension-function use;
- principal group cardinality and entity hierarchy depth;
- match density, including requests matching many permits or forbids;
- schema size and validation complexity;
- namespaces, resource attributes, and request context;
- listing calls that clone many matches or `policies()` calls that clone the
  complete set.

The deterministic corpus mixes permits, forbids, groups, exact constraints,
resource conditions, annotations, and strict schema validation, but it cannot
stand in for every production distribution.

## Initial Baseline

These measurements were collected in release mode on a shared Linux host with
an Intel Xeon Silver 4216 at 2.10 GHz, 16 physical cores/32 threads, Rust 1.97.1,
and Cedar 4.12.0. They are reference observations, not enforced thresholds. The
scheduled workflow uses the project's Rust 1.93.1 MSRV, so its results should be
compared within that environment rather than directly against this local run.

### Scaling Probe

| Policies | Validated load | Atomic reload | Evaluate allow median | Evaluate no-match median | Post-load RSS delta | Reload peak above loaded RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 0.159 s | 0.165 s | 1.258 ms | 1.253 ms | 15.6 MiB | 7.3 MiB |
| 10,000 | 1.613 s | 1.672 s | 13.454 ms | 13.918 ms | 104.5 MiB | 73.2 MiB |
| 100,000 | 16.367 s | 17.115 s | 164.315 ms | 163.691 ms | 995.9 MiB | 727.9 MiB |

The 100,000-policy probe used 25 measured request operations after one warm-up.
Its whole process consumed 52.82 seconds of user CPU and 0.80 seconds of system
CPU over 53.81 seconds elapsed, with 1,802,648 KiB maximum RSS. The process was
effectively CPU-bound for the run.

### Detailed 100,000-Policy Criterion Reference

| Operation | Median estimate |
| --- | ---: |
| Parse policies | 2.046 s |
| Parse and strictly validate | 9.214 s |
| Build engine without schema | 9.917 s |
| Build schema-validated engine | 17.215 s |
| Atomic schema-validated reload | 17.197 s |
| Evaluate allow | 168.97 ms |
| Evaluate forbid | 168.48 ms |
| Evaluate group membership | 166.57 ms |
| Evaluate no match | 171.21 ms |
| List no match | 29.86 ms |
| Clone all policies | 36.05 ms |

Criterion isolates operations and repeats them for regression analysis, while
the scale probe reports one process's phase memory and concise median/p95
latencies. Small differences between their latency values are expected.

### Preliminary Allocation Profile

A Valgrind Massif pass over the 1,000-policy probe found approximately 17.0 MiB
of useful heap at the atomic-reload peak. The largest named branches were Cedar
parser/CST policy nodes (about 4.54 MiB), parser variable-definition vectors
(about 2.88 MiB), and annotation trees (about 1.78 MiB). Together those three
branches represented roughly 54% of useful heap at that instant. Permit metadata
and JSON allocations were visible but were not the largest individual branches.

This first profile indicates that transient parse structures, compiled policy
state, annotations, and Treetop metadata must be measured separately. It would be
premature to treat permit metadata as the sole memory cause. Massif's live heap
later returned close to one-snapshot levels while process RSS remained elevated,
which also supports tracking live heap and allocator-retained RSS as distinct
metrics.

## Running the Measurements

Run the semantic test at a selected scale:

```bash
TREETOP_SCALE_POLICY_COUNT=100000 \
  cargo test --release --locked --all-features --test policy_scale \
  configured_policy_scale_loads_evaluates_lists_and_reloads \
  -- --ignored --exact --nocapture
```

Run the concise CPU-sensitive latency and memory probe. On Linux,
`/usr/bin/time -v` adds total user/system CPU and maximum RSS to the phase report:

```bash
TREETOP_SCALE_POLICY_COUNT=100000 \
TREETOP_SCALE_PROBE_SAMPLES=25 \
  /usr/bin/time -v cargo bench --locked --bench policy_scale_probe
```

Run the longer Criterion suite:

```bash
TREETOP_SCALE_POLICY_COUNT=100000 \
  cargo bench --locked --bench policy_scale_criterion -- --noplot
```

The probe reads Linux `VmRSS` and `VmHWM` from `/proc/self/status`. Other
platforms still report latency but mark phase memory as unavailable.

## Performance Investigation Priorities

The initial measurements point to five work streams:

1. **Transient versus steady memory.** Attribute parsing, CST conversion, schema
   validation, compiled Cedar state, annotations, permit/forbid metadata, and
   allocator retention separately. RSS alone cannot identify which component is
   live or reusable.
2. **Permit metadata memory.** Measure stored literals, stored JSON, IDs, and hash
   maps independently. Evaluate compact or lazy metadata representations without
   moving serialization back onto every allow decision or changing public
   response shapes accidentally.
3. **Authorization candidate work.** Determine whether Cedar or Treetop can
   safely narrow the policies considered for a request. Any indexing or
   partitioning must preserve forbid precedence, group semantics, conditions,
   and fail-closed behavior. Never select an authorization shard using
   untrusted client assertions.
4. **Concurrent throughput and tails.** Add controlled 1/2/4/8/16-thread tests
   for throughput, p95/p99 latency, memory bandwidth, and observability-enabled
   behavior. Single-thread medians are insufficient for service capacity.
5. **Reload retention and admission.** Measure repeated reloads, in-flight
   evaluations spanning swaps, allocator reuse, and multiple retained snapshot
   generations. Use those results to decide whether reload coalescing,
   backpressure, or explicit operational limits are needed.

Optimization work should keep the corpus and measurement protocol stable, add a
focused benchmark for the changed component, and rerun both the scale probe and
semantic test. Code shape alone is not evidence of improvement.
