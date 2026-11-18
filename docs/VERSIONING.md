# YuKKi OS — Versioning

## Current baseline

- **Proposed release line:** `v6.11.0`
- **Cargo package version:** `6.11.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** candidate; tag is pending required CI and release validation

## Policy

- The v6.11.0 minor bump covers the browser-WASM spatial/motion feature set,
  domain-neutral data workflows, and data-driven benchmark instrumentation.
- Do not create or publish the `v6.11.0` tag until required workflows pass and
  the release candidate is reviewed.
- Preserve the package/library name and runtime executable name for
  compatibility.
- Historical release notes remain in `docs/RELEASE_v*.md` and are archival.
  Historical references must be explicitly labeled as legacy/historical.

## Historical lines

- `v6.10.0` — current previously published baseline
- `v6.9.8` — archived in [RELEASE_v6.9.8.md](RELEASE_v6.9.8.md)
- `v6.9.6` — archived in [RELEASE_v6.9.6.md](RELEASE_v6.9.6.md)
- `v6.9.3` — archived in [RELEASE_v6.9.3.md](RELEASE_v6.9.3.md)
- `v6.9.0`, `v6.7.0`, `v6.6.6`, `v6.6.4` — archived

## Compatibility note

The executable name remains `yukki_core_node`. The browser application uses
`wasm32-unknown-unknown`; the WASI guest-worker artifact remains a separate
`wasm32-wasip1` build. Existing YKMC, BRK1/BRK2, NXR1, and WSM1 contracts are
not versioned or replaced by this package bump.
