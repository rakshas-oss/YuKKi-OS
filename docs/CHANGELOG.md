# Changelog

## Unreleased

## v6.13.1 (release candidate; tag pending)

### Browser-WASM benchmark hardening

- Added bounded CLI validation: at most 1,000 iterations, 1,024 operations
  and the fixed 512-entity spatial capacity; broker ports and device
  preferences are range/enum checked.
- Hardened manifest, dataset and profile validation, including size ceilings,
  IDs, finite spatial outputs, resolver success and simplifier result bounds.
- Added an optional Node-to-Overhauled BRK2 benchmark leg. It sends
  host-prepared numeric records as ordinary inference requests and verifies
  response schema, request/task correlation, success status, backend identity,
  selected-GPU consistency, output bounds and deterministic CPU results.
- Reports now explicitly distinguish local-only Wasm measurements from live
  broker interoperability. They do not claim WSM1 guest execution, browser
  rendering, streaming, NUMA scheduling, or physical accelerator qualification
  unless the relevant path is separately exercised.

### Interoperability documentation and architecture maps

- Clarified the browser-WASM benchmark bridge as direct BRK2 inference traffic,
  separate from production WSM1 guest/task lifecycle operations.
- Added step-by-step instructions for running the optional CPU-only broker
  round trip and interpreting backend/fallback telemetry.
- Added ANSI-inspired full-colour SVG architecture maps and terminal
  renderers for both repositories, distinguishing library primitives from
  daemon/HTTP features and preserving the YuKKi-OS/Overhauled responsibility
  boundary.
- Preserved YKMC, BRK1/BRK2, NXR1 and WSM1 wire contracts.

### Release metadata and qualification

- Bumped the native Cargo package/root lockfile, OCI image label, library
  banner and version metadata assertion to 6.13.1.
- v6.13.1 remains a candidate until required workflows pass and the release
  commit is reviewed. v6.13.0 remains the latest published release.
- Benchmark improvements are qualification-tool improvements; no universal
  throughput, latency, power or OPEX gain is claimed.

## v6.13.0 (published 2026-11-18)

### Native composed WebAssembly programs

- Added `CompositionRuntime` to assemble one or more live policy programs
  from a validated directed acyclic graph of core-Wasm modules and typed
  function imports.
- Added SHA-256 content-addressed, bounded in-process module caching and
  isolated per-replica Wasmtime Stores. Multi-replica execution requires an
  explicit `stateless: true` manifest declaration.
- Added atomic process-local activation of a prepared multi-program release;
  failed preparation leaves the active release unchanged, while already
  admitted calls retain their previous program set until completion.
- Added time-weighted replica ranking with stable SplitMix64 logical affinity,
  7/8 prior plus 1/8 latest-sample service-time EWMA, a 25% non-locality
  penalty and non-blocking Store admission. Full saturation returns an
  explicit `ProgramSaturated` error.
- Clarified that logical shard affinity is not geographic scheduling or
  physical NUMA pinning, and that composition remains a library API without a
  built-in CLI or HTTP deployment endpoint.

### Documentation and release metadata

- Aligned the architecture and sysadmin guides with the separate
  `ModuleLifecycleManager` and `CompositionRuntime` APIs, including exact
  scheduler scoring behavior and a WAT-to-Wasm build sequence.
- Updated the API reference, README, changelog, versioning guide, Cargo
  package/lockfile, OCI label and version metadata test to `6.13.0`.
- Preserved the YuKKi-OS/Overhauled boundary and existing YKMC, BRK1/BRK2,
  NXR1 and WSM1 protocol contracts.

---

## v6.12.0 (published 2026-11-18)

### Manifest-driven multivariate datasets and benchmark policy

- Added a bounded native JSON/JSONL manifest pipeline. Source rows and declared
  feature fields are the benchmark inputs; profiles define warm-up/sample
  windows, batch sizes, worker counts, objectives, and optional latency limits.
- Added `yukki_dataset_bench` to run NXR1 encode/decode and domain-scoped
  geospatial workload measurements across drone, finance, and environmental
  records. Reports preserve source identity, throughput/latency, working-set
  estimates, checksums, and the measured candidate selected by each profile.
- Connected measured dataset recommendations to YuKKi-OS bounded queue-policy
  APIs without changing broker/protocol wire formats or creating an artificial
  second dataset.

### Native symmetric numerics

- Added a bounded cyclic-Jacobi real-symmetric eigensolver for finite matrices
  with dimensions 1..=64. It returns ascending eigenvalues, column eigenvectors,
  residual and orthogonality diagnostics, and explicit failures for invalid,
  asymmetric, non-finite, overflowed, or non-convergent input.
- Added a domain-checked real arcsecant mapping, defined only for finite
  eigenvalues with `|lambda| >= 1`; this mapping is an optional representation,
  not a replacement for the eigensolver.
- Added `yukki_eigensolver_bench`, which consumes the same manifest feature
  fields, builds bounded correlation-matrix batches, measures throughput and
  P95 latency, and reports numerical quality alongside the selected candidate.
- Kept the numerical implementation in YuKKi-OS. Overhauled can measure
  broker/backend execution through its existing adapter and must not duplicate
  the eigensolver algorithm. No GPU/NPU acceleration or power-opex reduction
  is claimed by this CPU reference implementation.

### Browser spatial, spatiotemporal, and WASM workflows

- Documented the browser-WASM WGS84/ECEF and ENU transforms, Hermite
  interpolation, bounded 512-entity store, antimeridian-aware bounding boxes,
  freshness/distance-constrained nearest-observation resolution, and iterative
  arc–secant–tangent trajectory simplification.
- Added a user how-to for the browser spatial panel and the Manifest of Drones
  schema as a domain-neutral catalogue for drone telemetry, finance/market-site
  data, environmental mapping, real-estate observations, and similar
  multivariate sources. Full domain attributes and provenance remain on the
  host side; the spatial WASM ABI carries only the required spatial identity
  and time fields.
- Preserved the separate YuKKi-OS and Overhauled repositories, plus existing
  YKMC, BRK1/BRK2, NXR1, and WSM1 wire contracts.

### Benchmark infrastructure and release metadata

- Retained fixture-driven Criterion microbenchmarks and the browser-WASM Node
  runner that instantiates the actual compiled `wasm32-unknown-unknown`
  module. Native Criterion and browser-WASM CI reports remain diagnostic;
  shared-host timing thresholds are not used.
- Bumped the Rust package, root lockfile entry, OCI image label, README,
  versioning guide, API reference, and version assertion to `6.12.0`.
- Kept browser-WASM package versioning and the WASI guest artifact independent.

## v6.11.0 (superseded merged candidate; no tag published)

- Integrated the first browser spatial/spatiotemporal and native Criterion
  fixture candidate.
- This merged candidate was superseded before release tagging after required
  CI validation exposed benchmark type, ownership, and formatting defects.
  No `v6.11.0` release artifact or tag should be treated as published.

## v6.10.0 (last published release before the v6.11.0/v6.12.0 candidates)

### Event-driven draining, mesh validation, and NXR1 interoperability

- Replaced polling in WASM module draining with event-driven
  `tokio::sync::Notify` wakeups registered before counter inspection.
- Rejected non-finite mesh coordinates before R-tree insertion.
- Validated peer-advertised address lengths before broadcasting node-fleet
  updates.
- Hardened remote stream relay sequence arithmetic and validated complete
  upstream batches before mutating the mirror.
- Added real 256-byte NXR1 encode/decode Criterion benchmarks.
- Rejected negative WASM bridge timeouts before invoking the host handler.

---

## v6.9.5 (archived)

### Remote stream relay and dashboard

- Added `StreamRelay` to mirror discovered remote streams locally with shared,
  rate-limited upstream pulls, plus `OriginChunkClient` for authenticated HTTP
  metadata and chunk-range requests.
- Added the gateway stream dashboard at `/dashboard`; the static page is
  public, while stream data still requires the bearer token.
- Applications opt in by wiring a relay into `serve_with_relay`; the CLI does
  not configure an origin or relay automatically.
- The origin client uses plain HTTP with bounded I/O and response sizes; use a
  trusted network or TLS-terminating proxy. Origin descriptors omit codec
  metadata, so `OriginChunkClient` reports the codec as `unknown`.
