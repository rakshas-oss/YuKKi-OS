# Changelog

## Unreleased

### Stream selection, gateway, discovery, and WASM access

- Added `StreamRegistry` descriptors derived from live store lifecycle snapshots,
  bounded per-subscriber cursors, aggregate acknowledgements, hop-limited
  announcement deduplication, stale-entry expiry, and SHA-256 anti-entropy
  digests.
- Added authenticated HTTP list/describe/range endpoints and an ack-driven
  WebSocket chunk endpoint. Added gateway and `streams list`/`streams tune`
  CLI commands; gateway startup requires `YUKKI_GATEWAY_TOKEN` unless the
  explicit `--insecure-dev` option is used.
- Nodes relay bounded stream announcements and digest messages over the
  existing authenticated encrypted bootstrap transport. Discovery does not
  relay media chunks: remote tune-in and shared upstream pulls remain
  unsupported.
- Added the optional Wasmtime `env::yukki_select_stream` host import, which
  copies one bounded encoded YKMC chunk from a host store into validated guest
  memory without exposing native pointers.
- Added registry, gateway HTTP/WebSocket/auth, subscriber backpressure, and
  WASM selector tests; documented operational limits and TLS reverse-proxy
  guidance.

### NXR1 geospatial frame interoperability

- Added `src/nxr1.rs`: a dependency-free NXR1 binary codec for
  `geospatial.frame.v1` messages, matching the `rakshas-oss/overhauled`
  wire contract (magic `0x4E585231`, version `1`, big-endian fixed
  geospatial/velocity/fluidity/drag/divergence fields, `u32` BE
  length-prefixed opaque payload).
- Added `to_broker_task`/`from_broker_task` adapters that carry an
  `Nxr1Frame` inside the existing `BrokerTask` JSON envelope (kind
  `geospatial.frame.v1`) over the existing `BrokerClient` TCP transport,
  rather than introducing a second, conflicting binary protocol.
- Re-exported the new types from `src/lib.rs` alongside the existing
  `broker_client` exports.
- Added unit tests (in `src/nxr1.rs`) and an integration test
  (`tests/test_nxr1.rs`) covering round trips plus malformed input:
  truncation, bad magic/version, trailing bytes, oversized payload, and
  non-finite numbers.
- Documented the wire contract and adapter usage in `docs/API.md`.

## v6.9.3 (current)

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
