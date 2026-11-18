# YuKKi OS — Versioning

## Current baseline

- **Proposed release line:** `v6.12.0`
- **Cargo package version:** `6.12.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** candidate; tag and release archives are pending required CI and review

## Policy

- The v6.12.0 minor release groups the browser-WASM spatial/motion path,
  manifest-driven multivariate dataset execution, native benchmark-based policy
  selection, and the bounded real-symmetric eigensolver.
- Dataset manifests and source JSONL records are the workload inputs. Benchmark
  profiles select bounded execution policies from measured candidates; the
  benchmark path must not silently replace source records with random samples.
- YuKKi-OS owns dataset semantics, coordinate transforms, and eigensolver
  correctness. Overhauled remains a separate execution/placement tier and must
  not duplicate the eigensolver implementation.
- Do not create or publish the `v6.12.0` tag or release archives until the
  required workflows pass and the candidate receives release review.
- Preserve the package/library name and runtime executable name for
  compatibility.
- Historical release notes remain in `docs/RELEASE_v*.md` and are archival.
  Historical references must be explicitly labeled as legacy/historical.

## Historical lines

- `v6.11.0` — superseded merged candidate; no tag or release was published
- `v6.10.0` — last published baseline before the v6.11.0/v6.12.0 candidates
- `v6.9.8` — archived in [RELEASE_v6.9.8.md](RELEASE_v6.9.8.md)
- `v6.9.6` — archived in [RELEASE_v6.9.6.md](RELEASE_v6.9.6.md)
- `v6.9.3` — archived in [RELEASE_v6.9.3.md](RELEASE_v6.9.3.md)
- `v6.9.0`, `v6.7.0`, `v6.6.6`, `v6.6.4` — archived

## Compatibility note

The executable name remains `yukki_core_node`. The browser application uses
`wasm32-unknown-unknown`; the WASI guest-worker artifact remains a separate
`wasm32-wasip1` build. Existing YKMC, BRK1/BRK2, NXR1, and WSM1 contracts are
not versioned or replaced by this package bump.
