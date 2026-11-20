# YuKKi-OS — Versioning

## Current release candidate

- **Proposed release line:** `v6.14.0`
- **Cargo package version:** `6.14.0`
- **OCI image version:** `6.14.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** minor candidate; tag, release archives and external publication are pending

## Version assessment

The 6.14.0 minor increment follows the published v6.13.0 baseline and
incorporates the benchmark qualification/documentation work in PRs #143–#145
plus the worker-directive integration in PR #147.

PR #147 adds public workload classes and validated worker directives, derives
stable logical spatial affinity from resolved NXR1 routes, carries advisory
NUMA hints, maps existing TaskProfile semantics to worker classes, and
converts relative deadlines to checked absolute Unix-nanosecond BRK2 deadlines.
The Rust BRK2 codec transmits optional fields 11–13. The explicit WSM1 task
submission API requires BRK2 when a directive is supplied and returns optional
broker worker telemetry. Lifecycle operations use Control; generic BRK2 WSM1
tasks default to Throughput; inference callers must opt in explicitly.

This is a new public native API and cross-repository runtime capability, so a
minor increment to 6.14.0 is more accurate than a patch increment. Existing
YKMC, BRK1, BRK2, NXR1 and WSM1 envelope identities and existing required
fields remain compatible. Browser-WASM, WASI guest-worker and native-host
composition remain distinct execution surfaces.

## Release policy

- The last verified published baseline is v6.13.0.
- The earlier v6.13.1 patch candidate is superseded by this feature candidate;
  do not describe v6.13.1 as published unless its tag/release is independently
  verified.
- Do not create or publish v6.14.0 until native platform tests, browser-WASM
  build/smoke benchmark, WASI worker, format/Clippy, security, coverage,
  integration and live C++ BRK interoperability checks pass and the release
  commit is reviewed.
- Preserve the package/library name `yukkios` and runtime executable name
  `yukki_core_node`.
- The root Cargo package, root lockfile entry, OCI image label, library banner
  and version assertion must remain synchronized.
- Browser-WASM and WASI guest-worker artifacts retain their separate targets
  and package/build contracts. Their own package versions are not implicitly
  changed by the native crate version bump.
- Existing YKMC, BRK1/BRK2, NXR1 and WSM1 wire contracts remain independently
  versioned; optional worker TLVs do not replace those contracts.
- YuKKi-OS owns workload semantics and policy directives. Overhauled owns
  local class queues, admission budgets, CPU/NUMA affinity, backend selection
  and execution. A logical spatial key or NUMA hint is advisory, not a promise
  of physical placement.

## Published release history

- `v6.13.0` — published 2026-11-18; native Wasm program composition and
  time-weighted spatial replica pools.
- `v6.12.0` — published 2026-11-18; browser spatial/motion, multivariate
  datasets and the bounded symmetric eigensolver.
- `v6.11.0` — superseded merged candidate; no tag or release was published.
- `v6.10.0` — previous published baseline before v6.12.0.
- `v6.9.8`, `v6.9.6`, `v6.9.3` and earlier archived lines are documented
  in the corresponding historical release files.
