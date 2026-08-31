# Changelog

---

## v6.6.6 — Inet3 Edition

**Release focus:** Documentation and branch-alignment refresh for v6.6.6, including transition from Apex naming to Inet3 across project documentation.

### New Features

- **ADI Dynamic Integration auto-tuning suite** (`src/adi_auto_tune.rs`)
  - Benchmarks encoding throughput (10 000-frame test) and queuing efficiency (1 000-frame test) at startup
  - Dynamically selects optimal queue depth and hardware profile string
- **Virtual PUF — Micro-Timing Anchor**
  - High-resolution timing jitter measured at boot to seed device-unique entropy
  - Not predictable across hardware instances
- **Rustasm WebAssembly Sandbox** (`src/wasm_sandbox.rs`)
  - Wasmtime-backed isolated execution for untrusted modules
  - Results returned without exposing host memory
- **Explicit volatile memory wiping** via `zeroize` crate
  - `ZeroizeOnDrop` on all ephemeral key material
  - `secure_wipe` helper for sensitive byte arrays
- **Epsilon-Threshold Failsafe**
  - Monitors Lorenz attractor divergence; resets to stable point when divergence exceeds threshold

### Improvements

- Upgraded to X25519-dalek v2.0 with `static_secrets` feature
- ChaCha20-Poly1305 AEAD on both control and data planes
- Polymorphic attractor-bound payload weave (Lorenz-keyed ChaCha20 keystream)
- 64-bit flat topology with strict opcode alignment

### Dependencies Added

- `x25519-dalek = "2.0"` with `static_secrets`
- `chacha20poly1305 = "0.10"`
- `wasmtime = "14.0"`
- `zeroize = "1.6"` with `derive`

---

## Archived Release Summaries

### v6.6.0 — Sentinel Mesh Edition

Dual-layer sentinel quarantine (soft/hard), X25519 ECDH, ChaCha20 polymorphic weave, TCP AEAD framing.

### v6.5.0 — Ephemeral Mesh Edition

X25519 ECDH + ChaCha20-Poly1305 AEAD control-plane security. Ephemeral session keys.

### v6.4.3 — OOB Integrity Edition

FNV-1a rolling hash, 60-frame OOB sync, node quarantine, ChaCha20 payload binding.

> Full source for archived versions is available in git history.
