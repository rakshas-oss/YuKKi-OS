# YuKKi OS — Architecture Reference

> Covers v6.6.0 Sentinel Mesh (current). See [VERSIONING.md](VERSIONING.md) for differences across releases.

---

## High-Level Overview

YuKKi OS is a dual-plane peer-to-peer system designed around spatiotemporal data streaming and ephemeral cryptographic sessions.

```
┌─────────────────────────────────────────────────────────┐
│                    YuKKi OS Node                        │
│                                                         │
│  ┌──────────────┐          ┌─────────────────────────┐  │
│  │ Control Plane│  TCP/TLS │     Remote Peer Node    │  │
│  │  (Rust/Tokio)│◄────────►│     Control Plane       │  │
│  └──────┬───────┘          └─────────────────────────┘  │
│         │ FFI                                            │
│  ┌──────▼───────┐                                       │
│  │  Data Plane  │                                       │
│  │  (C99 Core)  │                                       │
│  │ Lorenz Engine│                                       │
│  │ ChaCha Weave │                                       │
│  │ Sentinel Qrn │                                       │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

---

## Control Plane

**Language:** Rust (async, Tokio runtime)  
**File:** `yukkios_6_6_sentinel/src/main.rs`

- JSON-framed messages over raw TCP with a 4-byte big-endian length prefix.
- Every session begins with an X25519 ephemeral key exchange (one key-pair per session, never persisted).
- A lightweight KDF (XOR + rotate with a domain separator) derives the 32-byte session key from the shared ECDH secret.
- All subsequent messages are AEAD-encrypted with **ChaCha20-Poly1305**: `[u32 len BE][12-byte nonce][ciphertext + 16-byte tag]`.

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `Handshake` | Bidirectional | X25519 public-key exchange |
| `FluidMessage` | Peer → Peer | Encrypted text message |
| `WeaveAnnounce` | Broadcast | Polymorphic-woven payload announcement |
| `PeerList` | Bootstrap → Node | List of known peers |

---

## Data Plane

**Language:** C99  
**File:** `src/ffi/chaos_weave.c` (shared across versions, compiled by `build.rs`)

### Lorenz Attractor Engine

The data plane generates `SpatiotemporalFrame` structs driven by the Lorenz chaotic differential equations (σ=10, ρ=28, β=8/3 by default). Each frame carries:

- Lorenz state `(x, y, z)` and velocity `(u, v, w)`
- Fluidity and drag coefficients
- Divergence scalar
- A 16-byte payload slot

### Polymorphic Payload Weave

`chacha_weave_payload` XORs plaintext against a ChaCha20 keystream whose 256-bit key is mixed with the current Lorenz attractor state, producing a session-unique, attractor-bound cipherstream.

> **⚠ Note:** This is illustrative, not authenticated — replay and mutation attacks are possible.

---

## FFI Boundary

The Rust control plane calls into the C data plane via explicit `unsafe` FFI blocks. The ABI contract is defined in `src/ffi/laminar_api.h`.

Key exported C functions:

| Function | Description |
|----------|-------------|
| `chaos_engine_init` | Initialise Lorenz attractor with σ, ρ, β |
| `force_lorenz_resync` | Reset attractor state to (x, y, z) |
| `weave_spatiotemporal_frame` | Produce one frame with optional weave |
| `sentinel_quarantine_node` | Register a node in the quarantine registry |
| `sentinel_release_node` | Remove a node from quarantine |
| `secure_wipe` | Zeroize a memory region before free |

---

## Sentinel Quarantine System

A dual-layer registry (up to 256 entries) maintained in the C layer:

| Level | Name | Trigger | Effect |
|-------|------|---------|--------|
| 1 | Soft quarantine | Frame-hash mismatch | Messages logged and dropped |
| 2 | Hard quarantine | Re-quarantine of level-1 node | Connection rejected at handshake |

Rust code calls `sentinel_quarantine_node` / `sentinel_release_node` via FFI.

---

## Version Directory Layout

| Version | Directory | Notable Changes |
|---------|-----------|-----------------|
| v6.4.3 | `src/` (root) | FNV-1a rolling hash, 60-frame OOB sync |
| v6.5.0 | `yukkios_6_5_ephemeral/` | X25519 + ChaCha20-Poly1305 AEAD control plane |
| v6.6.0 | `yukkios_6_6_sentinel/` | Dual-layer sentinel quarantine, polymorphic weave |
| v6.6.4 | `scripts/deploy/` | Apex Synthesis; PUF anchor, Rustasm WASM sandbox, ADI auto-tuning |

---

## Build Pipeline

`build.rs` uses the `cc` crate to compile `chaos_weave.c` into a static library that is linked into the Rust binary at build time.

```
cargo build --release
   └─► build.rs invokes cc crate
         └─► compiles chaos_weave.c → libchaos_weave.a
               └─► linked into yukki_sentinel binary
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for full build instructions.
