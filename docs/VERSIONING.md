# YuKKi-OS — Versioning

## Current release candidate

- **Proposed release:** `v6.17.0`
- **Cargo package version:** `6.17.0`
- **OCI image version:** `6.17.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** candidate only; no v6.17.0 tag or release has been created

## Version assessment

The 6.17.0 minor increment follows published v6.16.0 and contains two
feature-bearing changes merged after that release:

- **PR #162 — conventional WASM import binding:** imports whose namespace
  exactly matches a module ID in the same composition program are bound
  automatically. Explicit namespace aliases remain supported. Inferred
  bindings still pass through dependency ordering, exact function-signature
  validation and linker registration. Unmatched namespaces and unsupported
  imports continue to fail validation.
- **PR #163 — authenticated WASM handoff contract v1:** adds the shared
  protocol document and JSON Schema for signed capability offers, prepare
  requests, decisions, receipts, cancellation and bounded artifact chunks.
  It specifies Ed25519/RFC 8785 signing, sender/audience binding, expiry and
  replay protection, artifact digests, capability negotiation, and distinct
  prepare/activate phases.

The handoff contract is a specification, not a completed transport or
deployment implementation. It does not add a network-facing receiver,
receiver-side cryptographic enforcement, durable replay storage, artifact
publisher provenance verification, or cross-repository activation. Do not
describe the feature as production-ready remote deployment.

The increment is additive and does not intentionally change YKMC, BRK1/BRK2,
NXR1 or WSM1 wire formats. The published v6.16.0 baseline remains available
and independently versioned protocol contracts are unchanged.

## Release policy

- v6.16.0 is the latest published YuKKi-OS release.
- Do not tag or publish v6.17.0 until native platform tests, browser-WASM
  build/smoke, WASI worker, formatting/Clippy, security, coverage, integration,
  live C++ BRK interoperability and performance benchmark checks pass and
  the release commit is reviewed.
- Validate the newly merged WASM composition import-inference test on the
  release commit.
- Validate the handoff JSON Schema and ensure documentation continues to
  distinguish specified behavior from implemented behavior.
- Preserve the package/library name `yukkios` and runtime executable name
  `yukki_core_node`.
- Keep Cargo.toml, the root Cargo.lock package entry, OCI image label,
  library banner and version assertion synchronized.
- Browser-WASM and WASI guest-worker artifacts retain their separate targets
  and package/build contracts. Their own package versions are not implicitly
  changed by the native crate version bump.
- YuKKi-OS owns workload semantics, spatial resolution and directives.
  Overhauled owns broker admission, local queues, CPU/NUMA placement,
  backend selection and execution.

## Published release history

- `v6.16.0` — published 2026-11-21; lease-based broker discovery and BRK2
  locality intent/result codec support.
- `v6.15.0` — published 2026-11-21; resolver and benchmark concurrency
  improvements.
- `v6.14.0` — published 2026-11-20; YuKKi workload directives and BRK2
  worker-class interoperability.
- `v6.13.0` — published 2026-11-18; native Wasm program composition and
  time-weighted spatial replica pools.
- `v6.12.0` — published 2026-11-18; browser spatial/motion, multivariate
  datasets and the bounded symmetric eigensolver.
- `v6.11.0` — superseded merged candidate; no tag or release was published.
- `v6.10.0` — previous published baseline before v6.12.0.
