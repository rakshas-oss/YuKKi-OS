# Changelog

## Unreleased

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

## v6.7.0 (current)

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
