# Changelog

## Unreleased

## v6.11.0 (current)

### Benchmark documentation

- Added a benchmark guide covering the native Criterion targets, baseline capture, reproducibility requirements, and the distinction between benchmark compilation and measured CI performance.
- Documented a separate measurement matrix for the browser-WASM spatial feature set without presenting unmeasured performance claims.


### Browser MMO spatial core and spatiotemporal resolution

- Added a bounded, portable spatial and motion core to the existing browser-WASM application, preserving the original YuKKi-OS and Overhauled repository boundary.
- Added WGS84/ECEF and ENU transforms, cubic Hermite interpolation, bounded entity storage, antimeridian-aware bounding-box queries, and freshness- and distance-constrained spatiotemporal nearest-observation resolution.
- Added iterative arc–secant–tangent path simplification with bounded storage, endpoint preservation, and sharp-turn protection.
- Exposed the MMO primitives through a stable browser-WASM ABI and integrated the local spatial resolver into the browser application and its smoke tests.
- Preserved existing YKMC, BRK1/BRK2, NXR1, and WSM1 interoperability boundaries.

## v6.10.0

### Event-driven draining, mesh validation, and NXR1 interoperability

- Replaced polling in WASM module draining with event-driven `tokio::sync::Notify` wakeups registered before counter inspection.
- Rejected non-finite mesh coordinates before R-tree insertion.
- Validated peer-advertised address lengths before broadcasting node-fleet updates.
- Hardened remote stream relay sequence arithmetic and validated complete upstream batches before mutating the mirror.
- Added real 256-byte NXR1 encode/decode Criterion benchmarks.
- Rejected negative WASM bridge timeouts before invoking the host handler.

---

## v6.9.5

### Remote stream relay and dashboard

- Added `StreamRelay` to mirror discovered remote streams locally with shared,
  rate-limited upstream pulls, plus `OriginChunkClient` for authenticated HTTP
  metadata and chunk-range requests.
- Added the gateway stream dashboard at `/dashboard`; its static page is public,
  while stream data requests still require the bearer token.
- Applications opt in by wiring a relay into `serve_with_relay`; the CLI does
  not configure an origin or relay automatically.
- The origin client uses plain HTTP, with bounded I/O and response sizes; use a
  trusted network or TLS-terminating proxy. Origin descriptors omit codec
  metadata, so `OriginChunkClient` reports the codec as `unknown`.

## v6.9.3

### Stream registry, gateway, discovery, and WASM access

- Added `StreamRegistry` descriptors derived from live store lifecycle snapshots,
  bounded per-subscriber cursors, aggregate acknowledgements, hop-limited
  announcement deduplication, stale-entry expiry, and SHA-256 anti-entropy
  digests.
- Added authenticated HTTP list/describe/range endpoints and an ack-driven
  WebSocket chunk endpoint. Added gateway and `streams list`/`streams tune`
  CLI commands; gateway startup requires `YUKKI_GATEWAY_TOKEN` unless the
  explicit `--insecure-dev` option is used.
- Nodes relay bounded stream announcements and digest messages over the
  existing authenticated encrypted bootstrap transport.
- Added the optional Wasmtime `env::yukki_select_stream` host import, which
  copies one bounded encoded YKMC chunk from a host store into validated guest
  memory without exposing native pointers.
- Added registry, gateway HTTP/WebSocket/auth, subscriber backpressure, and
  WASM selector tests; documented operational limits and TLS reverse-proxy
  guidance.

### Version bump and documentation refresh

- Bumped the Cargo package and active release baseline to `v6.9.3`, keeping
  the library crate name unchanged.
- Refreshed the README, version metadata, and deployment docs for the 6.9.3
  release line.
- Updated Docker image metadata and release references to match the active
  baseline.

## v6.9.0

### Streaming and documentation

- Bumped the Cargo package and active release baseline to `v6.9.0`, keeping
  the library crate name unchanged.
- Refreshed the README for v6.9.0 and added a streaming binaries and data
  section.
- Added `docs/USER_HOWTO_STREAMING.md` with user guidance for bounded media
  streams, broker delivery, GeoJSON/NXR1 frames, and WASM deployment.

## v6.8.0

### Version baseline refresh

- Bumped the Cargo package and active release baseline to `v6.8.0`
- Updated versioned crate and deployment helper identifiers
- Refreshed active documentation, examples, and version metadata references

## v6.7.0 (archived)

### NXR1 geospatial frame interoperability

- Added `src/nxr1.rs`: a dependency-free NXR1 binary codec for
  `geospatial.frame.v1` messages, matching the `rakshas-oss/overhauled`
  wire contract (magic `0x4E585231`, version `1`, big-endian fixed
  geospatial/velocity/fluidity/drag/divergence fields, `u32` BE
  length-prefixed opaque payload).
- Added `to_broker_task`/`from_broker_task` adapters to carry NXR1 frames in the
  existing `BrokerTask` JSON envelope and documented the wire contract in
  `docs/API.md`.

### Baseline cleanup and coherence refresh

- Normalized repository version baseline to `v6.7.0`
- Corrected stale `v6.6.6`/`v6.6.4` references in active docs and scripts
- Kept `yukki_core_node` executable name stable for compatibility
- Updated tests/benches to current crate name (`yukkios_6_7_0_inet3`)
- Replaced stale deploy script path with a maintainable v6.7.0 deployment wrapper
- Updated deployment/sysadmin docs to match actual CLI and supported configuration
- Refreshed architecture/API/security/versioning docs to match current code paths

### Validation status

Validation commands and benchmark outcomes for this refresh are documented in the task execution report and release notes context.

## Archived

- `v6.6.6` — see [RELEASE_v6.6.6.md](RELEASE_v6.6.6.md)
- `v6.6.4` — see [RELEASE_v6.6.4.md](RELEASE_v6.6.4.md)
