# YuKKi-OS v6.17.0 — Release Candidate

**Status:** CI-validated release candidate. PR #164 is merged; no v6.17.0
tag or GitHub release has been created, and no external package publication
is claimed.

## Highlights

- Automatically bind conventional core-Wasm imports when the import namespace
  exactly matches a module ID in the same composition program. Explicit
  bindings remain available for aliases, and inferred imports still undergo
  dependency ordering and exact signature validation.
- Define authenticated WASM handoff contract v1 with a shared JSON Schema for
  signed capability offers, prepare requests, decisions, receipts,
  cancellation and bounded artifact chunks.
- Specify Ed25519 signatures over RFC 8785 canonical JSON, sender/audience
  binding, expiry and replay checks, digest-verified transfer, backend
  capability negotiation, and separate prepare/activate phases.

## Compatibility and security boundaries

- Existing explicit WASM bindings retain their behavior; unmatched imports
  remain validation errors.
- No YKMC, BRK1/BRK2, NXR1 or WSM1 wire-format change is intended.
- The handoff contract is a protocol specification. It does not itself
  implement a network receiver, cryptographic enforcement, persistent replay
  storage, publisher provenance checks or distributed activation.
- The Overhauled shared-Store isolation limitation remains. Do not treat the
  contract as proof of tenant isolation or a production-ready remote execution
  service.

## CI validation — passed

All four required workflows passed on PR #164 head commit
`ced85a24636b35c2506f83a47ffd57cee918e996` (2026-11-22):

- **Test & Code Quality:** security audit, Clippy, Rustfmt, Linux/macOS/Windows
  unit tests, Docker build validation and coverage.
- **Multi-Platform Build:** Linux x86_64/aarch64/ARMv7/musl, macOS x86_64/arm64,
  WASI build/tests, browser-WASM formatting/tests/Clippy/build/export smoke and
  benchmark execution.
- **Integration Tests:** peer mesh, ADI calibration, GPU/WASM adapter,
  sandbox and crypto integration, ABI/FFI, browser-WASM broker smoke, simulated
  NPU/CPU fallback, and paired Overhauled BRK1/BRK2 conformance/live Rust-C++
  interoperability.
- **Coverage & Metrics:** code metrics, license compliance, dependency audit,
  coverage and Criterion performance benchmarks.

All four workflow conclusions were `success`. The versioned release archive
job was skipped because no release tag triggered it.

## Remaining release boundary

CI success validates the tested build and integration paths; it does not turn
the handoff contract into an implemented network receiver or prove durable
replay storage, publisher provenance verification or distributed activation.
Review the release metadata, then create a v6.17.0 tag/release as a separate
release action. No tag, GitHub release or external package publication is
created by this documentation update.
