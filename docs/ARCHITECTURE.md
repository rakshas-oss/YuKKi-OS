# YuKKi OS v6.6.4 — Architecture Reference

---

## Overview

YuKKi OS v6.6.4 (Inet3 Edition) is a dual-plane peer-to-peer system built in Rust with a C FFI layer for the Lorenz attractor engine.

```
┌─────────────────────────────────────────────────┐
│                  Application Layer               │
│  Bootstrap / Peer CLI  │  Interactive Prompt     │
└──────────────┬──────────────────────┬────────────┘
               │                      │
    ┌──────────▼──────────┐  ┌────────▼────────────┐
    │    Control Plane     │  │     Data Plane       │
    │  TCP + AEAD frames   │  │  SpatiotemporalFrame │
    │  JSON messages       │  │  88-byte binary      │
    │  X25519 ECDH handshk │  │  Lorenz attractor    │
    └──────────┬──────────┘  └────────┬────────────┘
               │                      │
    ┌──────────▼──────────────────────▼────────────┐
    │              Rust Runtime (main.rs)           │
    │  ADIAutoTuner │ WasmSandbox │ ZeroizeMemory   │
    └──────────────────────┬────────────────────────┘
                           │ FFI
    ┌──────────────────────▼────────────────────────┐
    │           C Layer (chaos_weave.c)              │
    │  lorenz_step │ chacha_weave_payload │ quarantine│
    └───────────────────────────────────────────────┘
```

---

## Control Plane

- **Transport:** Raw TCP with 4-byte big-endian length-prefixed frames
- **Encryption:** ChaCha20-Poly1305 AEAD (12-byte nonce, 16-byte tag)
- **Key Exchange:** X25519 ECDH — one ephemeral key-pair per session, never persisted
- **Messages:** JSON-encoded (`NodeAnnounce`, `FluidMessage`, `WeaveAnnounce`, `Heartbeat`)

### X25519 Handshake Flow

```
Node A                             Node B
  │──── pub_key_A (32 bytes) ────▶│
  │◀─── pub_key_B (32 bytes) ─────│
  │                                │
  shared = ECDH(priv_A, pub_B)    shared = ECDH(priv_B, pub_A)
  session_key = KDF(shared)       session_key = KDF(shared)
  │                                │
  │══════ AEAD frames ════════════▶│
```

---

## Data Plane

- **Frame:** `SpatiotemporalFrame` (88 bytes, `#[repr(C, packed)]`)
- **Engine:** Lorenz attractor (`chaos_weave.c`) — produces chaotic but deterministic frame sequences
- **Payload Weave:** `chacha_weave_payload` XORs arbitrary data against a Lorenz-keyed ChaCha20 keystream

### Lorenz Attractor Parameters

```
σ = 10.0,  ρ = 28.0,  β = 8/3
dt = 0.01 (default)
```

### Epsilon-Threshold Failsafe

```
if |divergence| > EPSILON_THRESHOLD:
    reset attractor to stable point (x=1, y=1, z=1)
    increment failsafe_counter
```

When the Lorenz state diverges beyond the epsilon threshold, the failsafe resets to a known stable point, preventing runaway divergence from corrupting frame generation.

---

## ADI Auto-Tuning Suite

```
startup
  │
  ├─ test_encoding_throughput()
  │    evaluate 10 000 frames
  │    target: < 15 ms
  │    result: bool (pass/fail)
  │
  └─ test_enquing_efficiency()
       queue 1 000 frames
       target: < 2 000 µs
       if pass → optimal_queue_depth = 120
       else    → optimal_queue_depth = 60  (default)
```

The `active_hardware_profile` string describes the detected environment (e.g., `"64-BIT_ELECTRICAL_FLAT"`).

---

## Rustasm WebAssembly Sandbox

```
WasmSandbox::new()
  │  Wasmtime Engine initialization
  │
WasmSandbox::execute(wasm_bytes)
  │  Compile WASM module
  │  Instantiate in isolated linear memory
  │  Call "main" export
  └─ Return i32 result or error
```

The sandbox provides hard memory isolation — WASM modules cannot access Rust heap or stack outside their own linear memory segment.

---

## Virtual PUF — Micro-Timing Anchor

At boot, a series of high-resolution timing measurements (`std::time::Instant`) captures environmental jitter. This timing fingerprint is unique per hardware instance and is mixed into the initial entropy pool.

```
t0 = Instant::now()
[tight loop N iterations]
t1 = Instant::now()
entropy_contribution = (t1 - t0).subsec_nanos() XOR device_constant
```

---

## Memory Wiping

All ephemeral key material uses the `zeroize` crate:

```rust
#[derive(ZeroizeOnDrop)]
struct SessionKey([u8; 32]);
```

On drop, `SessionKey` is overwritten with zeros before deallocation. The `secure_wipe` helper provides explicit wiping for ad-hoc byte arrays.

---

## FFI Boundary

The Rust–C boundary is defined in `src/ffi/laminar_api.h` and consumed via `extern "C"` declarations in Rust.

Safety invariants:
- C functions receive valid non-null pointers (checked at call site in Rust)
- Struct layout is ABI-stable (`#pragma pack(push,1)` ↔ `#[repr(C, packed)]`)
- No dynamic allocation in C hot paths

See [API.md](API.md) for full function signatures.
