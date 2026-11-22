# YuKKi-OS v6.17.0 — Published Release

**Status:** published 2026-11-22. The `6.17.0` tag points to release commit
`c07052f2011dc727c4a0cb7a0684a8ca435faa52`. The GitHub Release has 10 attached
assets. External package publication is not implied.

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

## Published assets

The GitHub Release includes Linux x86_64, ARM64, ARMv7 and x86_64-musl runtime
archives; macOS x86_64 and ARM64 runtime archives; the WASI guest-worker
archive; browser-WASM application and benchmark archives; and `SHA256SUMS`.
The tag points to the merged v6.17.0 release commit.

## Security and distribution boundary

The handoff contract remains a protocol specification, not an implemented
network receiver. The release does not provide receiver-side cryptographic
enforcement, durable replay storage, publisher provenance verification or
distributed activation. GitHub publication also does not imply publication to
external package registries.
