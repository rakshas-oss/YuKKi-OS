# YuKKi-OS v6.17.0 — Release Candidate

**Status:** candidate only. This document does not indicate that a tag or
release has been published.

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

## Release gate

Before tagging or publishing, require green native platform, browser-WASM,
WASI, formatting/Clippy, security, coverage, integration, BRK interoperability
and benchmark checks on the release commit. Verify the new inferred-import
composition test and validate the JSON Schema. Keep this candidate untagged
until review and all required checks pass.
