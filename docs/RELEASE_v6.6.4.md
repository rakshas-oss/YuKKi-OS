# v6.6.4 — Inet3 Edition (Legacy / Historical)

> **This release has been superseded by v6.6.6, the current canonical version.** Kept for historical reference only; see [RELEASE_v6.6.6.md](RELEASE_v6.6.6.md) and [VERSIONING.md](VERSIONING.md).

Tag: v6.6.4

Release date: 2026-08-13

Summary

v6.6.4 (Inet3 Edition) is a production release consolidating the v6.6.x development stream. It focuses on secure ephemeral key handling, improved isolated WebAssembly execution, hardware-tuned ADI integration, deterministic volatile-memory wiping, and operational failsafes for chaotic attractor divergence.

Highlights

- ADI Dynamic Integration auto-tuning suite (src/adi_auto_tune.rs)
  - Startup benchmarks for encoding throughput (10,000-frame test) and queuing efficiency (1,000-frame test).
  - Automatic selection of optimal queue depth and hardware profile.
- Virtual PUF — Micro-Timing Anchor
  - High-resolution timing jitter measured at boot used to seed device-unique entropy.
  - Designed to be non-predictable across hardware instances.
- Rustasm WebAssembly Sandbox (src/wasm_sandbox.rs)
  - Wasmtime-backed isolated execution for untrusted modules.
  - Execution results marshalled out without exposing host memory.
- Explicit volatile memory wiping via `zeroize`
  - `ZeroizeOnDrop` applied to ephemeral key material.
  - `secure_wipe` helper for sensitive byte arrays.
- Epsilon-Threshold Failsafe
  - Monitors Lorenz attractor divergence and resets state when divergence exceeds configured threshold.
- Cryptography & Performance
  - Upgraded to x25519-dalek v2.0 with `static_secrets` feature.
  - ChaCha20-Poly1305 AEAD used on both control and data planes.
  - 64-bit flat topology with strict opcode alignment.

Dependency changes

- Added: `x25519-dalek = "2.0"` (static_secrets)
- Added: `chacha20poly1305 = "0.10"`
- Added: `wasmtime = "14.0"`
- Added: `zeroize = "1.6"` (with `derive`)

Upgrade notes / breaking changes

- Key material lifecycle: Ephemeral secrets are now zeroed on drop. Code paths that rely on runtime retention of ephemeral secrets must be updated to preserve copies explicitly when required.
- X25519 behavior: Confirm compatibility with downstream users expecting previous x25519-dalek semantics.
- Wasm host requirements: Wasmtime 14.0 may impose host dependency changes; verify runtime environments.

Security

- All ephemeral key material is wiped using `zeroize` and ZeroizeOnDrop to reduce risk of memory-leak secrets.
- Wasm sandboxing isolates untrusted modules to minimize host memory exposure. Review sandbox policies for your deployment.

Testing checklist (required before publishing)

- [ ] Full CI integration test run covering X25519 + ChaCha20-Poly1305 flows
- [ ] Wasm sandbox fuzzing and isolation verification
- [ ] ADI auto-tune benchmarks on representative hardware (10k / 1k frame tests)
- [ ] Memory-sanitizer / ASAN run to confirm secure wipe behavior
- [ ] Regression tests for framing, topology alignment, and runtime stability

Release artifacts

- Tag: v6.6.4
- Binaries: linux-x86_64, linux-aarch64 (historical release; no prebuilt binaries are distributed)

Maintainers / contributors

- Release manager: rakshas-oss
- Full contributor list available from git history (see `git shortlog -sne`)
