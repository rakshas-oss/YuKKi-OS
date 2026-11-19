# YuKKi OS — Versioning

## Current release candidate

- **Proposed release line:** `v6.13.1`
- **Cargo package version:** `6.13.1`
- **OCI image version:** `6.13.1`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** patch candidate; v6.13.1 tag and release archives are pending required CI and review

## Version assessment

The patch increment follows the v6.13.0 release and the subsequent merged PRs:

- PR #143 hardened browser-WASM benchmark CLI limits, dataset/profile
  validation, finite spatial results, resolver/simplifier outputs, and added
  an optional live BRK2 inference leg with response validation and telemetry.
- PR #144 aligned the benchmark bridge and multivariate-data documentation,
  clarifying that local browser-WASM execution and direct BRK2 benchmark
  requests are distinct from the production WSM1 guest/lifecycle path.
- PR #145 added full-colour architecture diagrams and terminal ANSI renderers
  that make service ownership and implementation boundaries explicit.

These changes improve benchmark reliability, cross-repository qualification
and documentation. They do not change the public native runtime API, core
composition semantics, or YKMC/BRK1/BRK2/NXR1/WSM1 wire contracts. A patch
increment to 6.13.1 is appropriate; the composition and replica-scheduler
features remain part of the published v6.13.0 release.

## Release policy

- v6.13.0 is the latest published YuKKi-OS release.
- Do not create or publish v6.13.1 until the required native, browser-WASM,
  WASI, integration, security, coverage and benchmark checks pass and the
  intended release commit is reviewed.
- The optional browser benchmark broker mode is a qualification client. It
  does not add a public daemon route, enable the production GPU adapter, or
  send executable Wasm to Overhauled.
- Preserve the package/library name `yukkios` and runtime executable name
  `yukki_core_node`.
- Browser-WASM and WASI guest-worker artifacts retain their separate targets
  and package/build contracts. Their own package versions are not implicitly
  changed by the native crate version bump.
- Existing YKMC, BRK1/BRK2, NXR1 and WSM1 wire contracts remain independently
  versioned and are not replaced by the crate version.

## Published release history

- `v6.13.0` — published 2026-11-18; native Wasm program composition and
  time-weighted spatial replica pools.
- `v6.12.0` — published 2026-11-18; browser spatial/motion, multivariate
  datasets and the bounded symmetric eigensolver.
- `v6.11.0` — superseded merged candidate; no tag or release was published.
- `v6.10.0` — previous published baseline before v6.12.0.
- `v6.9.8`, `v6.9.6`, `v6.9.3` and earlier archived lines are documented
  in the corresponding historical release files.

