# YuKKi-OS — Versioning

## Current release candidate

- **Proposed release line:** `v6.15.0`
- **Cargo package version:** `6.15.0`
- **OCI image version:** `6.15.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** minor candidate; v6.15.0 tag and release archive are pending

## Version assessment

The 6.15.0 minor increment follows published v6.14.0 and adds parallel
workload capabilities across the resolver, composed-WASM scheduler and
benchmark harness:

- PR #151 changes `SpatiotemporalPayloadResolver` strict ordering from one
  route-wide critical section to a short source-state map lookup followed by
  per-source locking. Different sources can progress concurrently; strict
  ordering remains atomic per source.
- The strict resolver source-state map is bounded at 65,536 sources per route.
  The new `SequenceSourceLimit` error reports when the ceiling is reached;
  queue-full failures do not advance the source sequence watermark.
- `TimeWeightedSpatialScheduler::ranked_candidates_with_load` ranks replicas
  using service-time EWMA, current active-call load and the existing bounded
  locality preference. Store admission remains a non-blocking lock attempt.
- Native dataset and eigensolver benchmark workers now claim adaptive chunks
  and keep timing, checksum, residual and orthogonality metrics locally before
  merging after worker completion. This reduces shared instrumentation
  contention without suppressing numerical quality checks.

The PR adds a scheduler API and an explicit bounded-sequence-limit error path.
A minor increment to 6.15.0 is appropriate for this feature-bearing update.
The changes do not alter YKMC, BRK1/BRK2, NXR1 or WSM1 wire formats. They do not
claim lock-free queues, guaranteed linear scaling or zero-stall execution.

## Release policy

- v6.14.0 is the latest published YuKKi-OS release (2026-11-20).
- Do not create or publish v6.15.0 until native platform tests, browser-WASM
  build/smoke, WASI worker, format/Clippy, security, coverage, integration,
  live C++ BRK interoperability and performance benchmark checks pass and
  the release commit is reviewed.
- Preserve the package/library name `yukkios` and runtime executable name
  `yukki_core_node`.
- Keep Cargo.toml, the root Cargo.lock package entry, OCI image label,
  library banner and version assertion synchronized.
- Browser-WASM and WASI guest-worker artifacts retain their separate targets
  and package/build contracts. Their own package versions are not implicitly
  changed by the native crate version bump.
- Existing YKMC, BRK1/BRK2, NXR1 and WSM1 wire contracts remain independently
  versioned and unchanged by this release.
- YuKKi-OS owns workload semantics, spatial resolution and directives.
  Overhauled owns its local class/CPU-group queues, admission budgets,
  broker-local NUMA/CPU affinity, accelerator placement and execution.

## Published release history

- `v6.14.0` — published 2026-11-20; YuKKi workload directives and BRK2
  worker-class interoperability.
- `v6.13.0` — published 2026-11-18; native Wasm program composition and
  time-weighted spatial replica pools.
- `v6.12.0` — published 2026-11-18; browser spatial/motion, multivariate
  datasets and the bounded symmetric eigensolver.
- `v6.11.0` — superseded merged candidate; no tag or release was published.
- `v6.10.0` — previous published baseline before v6.12.0.
- `v6.9.8`, `v6.9.6`, `v6.9.3` and earlier archived lines are documented
  in the corresponding historical release files.

