# YuKKi OS — Versioning

## Current release candidate

- **Proposed release line:** `v6.13.0`
- **Cargo package version:** `6.13.0`
- **OCI image version:** `6.13.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** candidate; tag and release archives are pending required CI and review

## Policy

- The v6.13.0 minor release adds native multi-module WebAssembly program
  composition and time-weighted replica pools for declared policy programs.
- Composition is owned by YuKKi-OS's native Wasmtime host. Overhauled remains a
  separate broker/execution and accelerator-placement tier; its WSM1 lifecycle
  API does not compile, link or merge guest modules.
- Composition v1 accepts a declared DAG of core-Wasm modules with typed
  function imports. The default is one stateful replica. Multi-replica
  execution requires an explicit `stateless: true` application declaration.
- Replica selection combines a stable logical affinity key with measured
  service-time EWMA. The key is not geographic routing or physical NUMA
  placement. Full saturation is reported explicitly; it is not a zero-stall
  guarantee.
- Do not create or publish the `v6.13.0` tag or release archives until the
  required workflows pass and the candidate receives release review.
- Preserve the package/library name and runtime executable name for
  compatibility. Browser-WASM and WASI guest artifacts retain their separate
  target and packaging contracts.

## Historical lines

- `v6.12.0` — last published release; browser-WASM spatial/motion, native
  benchmark-driven multivariate datasets, and bounded real-symmetric
  eigensolver.
- `v6.11.0` — superseded merged candidate; no tag or release was published
- `v6.10.0` — previous release baseline before v6.12.0
- `v6.9.8` — archived in [RELEASE_v6.9.8.md](RELEASE_v6.9.8.md)
- `v6.9.6` — archived in [RELEASE_v6.9.6.md](RELEASE_v6.9.6.md)
- `v6.9.3` — archived in [RELEASE_v6.9.3.md](RELEASE_v6.9.3.md)
- `v6.9.0`, `v6.7.0`, `v6.6.6`, `v6.6.4` — archived

## Compatibility note

The executable name remains `yukki_core_node`. The browser application uses
`wasm32-unknown-unknown`; the WASI guest-worker artifact remains a separate
`wasm32-wasip1` build. Existing YKMC, BRK1/BRK2, NXR1, and WSM1 contracts are
not versioned or replaced by this package bump.
