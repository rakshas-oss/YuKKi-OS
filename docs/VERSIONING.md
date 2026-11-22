# YuKKi-OS — Versioning

## Current published release

- **Published release:** `v6.17.0`
- **Cargo package version:** `6.17.0`
- **OCI image version:** `6.17.0`
- **Rust toolchain pin:** `1.98.1`
- **Runtime binary name:** `yukki_core_node`
- **Release state:** published 2026-11-22; GitHub Release contains 10 assets

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

## CI validation — v6.17.0

PR #164 merged the version metadata candidate. All four required workflows
completed successfully on PR head commit `ced85a24636b35c2506f83a47ffd57cee918e996`
(2026-11-22):

- Test & Code Quality — security audit, Clippy, Rustfmt, native unit tests on
  Linux/macOS/Windows, Docker build validation and code coverage.
- Multi-Platform Build — Linux x86_64/aarch64/ARMv7/musl, macOS x86_64/arm64,
  WASI Preview 1 build/tests, browser-WASM tests/Clippy/build/export smoke and
  benchmark run.
- Integration Tests — mesh/network, ADI calibration, GPU/WASM adapter,
  sandbox, cryptography, ABI/FFI, browser-WASM-to-broker smoke, simulated NPU
  and CPU fallback, plus paired Overhauled BRK1/BRK2 conformance and live
  Rust-to-C++ round trips.
- Coverage & Metrics — code metrics, license compliance, dependency audit,
  coverage upload and Criterion performance benchmarks.

All required workflow conclusions were `success`. The pull-request CI run skipped its release-archive job because it was not a
release-tag event. After merge, tag `6.17.0` was published against release
commit `c07052f2011dc727c4a0cb7a0684a8ca435faa52`; the GitHub Release then
attached 10 assets: native Linux x86_64, ARM64, ARMv7 and musl binaries,
macOS x86_64 and ARM64 binaries, the WASI guest worker, browser-WASM app and
benchmark archives, and `SHA256SUMS`.

## Release policy

- v6.17.0 is the latest published YuKKi-OS release (2026-11-22).
- External package publication, where applicable, is separate from the GitHub
  Release and must be verified independently.
- Keep the handoff protocol documentation explicit about which behavior is
  specified and which receiver/runtime behavior is implemented.
- Keep the handoff JSON Schema and protocol claims scoped to the actual
  specification; green CI does not prove the not-yet-implemented network
  receiver, durable replay storage, publisher provenance checks or distributed
  activation.
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
