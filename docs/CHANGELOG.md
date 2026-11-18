# Changelog

## Unreleased

## v6.11.0 (release candidate; tag pending)

### Browser spatial and spatiotemporal feature set

- Consolidated the existing browser-WASM spatial and motion path in the
  release documentation: WGS84/ECEF and ENU transforms, Hermite interpolation,
  a bounded 512-entity store, antimeridian-aware bounding-box queries, and
  freshness/distance-constrained nearest-observation resolution.
- Documented the iterative arc–secant–tangent trajectory simplifier, including
  chord/arc deviation, tangent-turn protection, bounded storage, and
  retained-point reporting.
- Added a user how-to showing how the drone manifest can catalogue multivariate
  sources such as drone telemetry, finance/market-site data, environmental
  monitoring, and real-estate records. Domain attributes remain in host-side
  records; the spatial ABI accepts only identity, location, time, and radius.
- Preserved the separate YuKKi-OS control-plane and Overhauled execution-plane
  repositories and the existing YKMC, BRK1/BRK2, NXR1, and WSM1 boundaries.

### Data-driven performance measurement

- Made a versioned JSON fixture the input source for native Criterion suites.
- Added deterministic synthetic drone, finance-site, and environmental
  profiles for the browser-WASM benchmark runner, with 16/128/512 entity and
  path sizes.
- Added a Node runner that instantiates and measures the actual compiled
  `wasm32-unknown-unknown` module, including spatial queries, transforms,
  interpolation, and arc–secant–tangent simplification.
- Updated CI to run native Criterion measurements and browser-WASM workloads
  and upload their reports. CI artifacts are diagnostic and do not impose
  unstable shared-runner performance thresholds.

### Release metadata and documentation

- Bumped the Rust package and lockfile root package to `6.11.0`.
- Aligned README, Docker image metadata, versioning, API, browser, and
  benchmarking documentation.
- Kept browser-WASM package versioning and WASI guest artifacts independent.

## v6.10.0 (previous release)

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

