# YuKKi OS — Ephemeral Mesh & Spatiotemporal Weave

Linux-based P2P application with dependency-aware runtime behavior for Internet 3.

---

## Versions

| Version | Directory | Highlights |
|---------|-----------|------------|
| 6.5.0 Ephemeral Mesh | `yukkios_6_5_ephemeral/` | X25519 ECDH + ChaCha20-Poly1305 AEAD control-plane security |
| 6.4.3 OOB Integrity | (root `src/`) | FNV-1a rolling hash, 60-frame OOB sync, node quarantine |

---

## Overview — v6.5.0 Ephemeral Mesh

YuKKi OS 6.5.0 is a dual-plane peer-to-peer system with ephemeral session security:

- **Control Plane** — JSON over TCP/WebSocket, secured with X25519 ECDH key exchange and ChaCha20-Poly1305 AEAD encryption.
- **Data Plane** — Binary `SpatiotemporalFrame` tensor stream driven by a Lorenz attractor.
- **C FFI Core** — Lorenz-state evolution, Pauli binding shim, FNV-1a OOB integrity, ephemeral KDF mixing Lorenz state with X25519 shared secret.
- **Rust Node Runtime** — async Tokio networking, WebSocket bootstrap sync, interactive shell.

> Ephemeral keys are never persisted to disk; each session derives a fresh key.

---

## Repository Structure

```text
yukkios_6_5_ephemeral/        ← v6.5.0 Ephemeral Mesh
├── Cargo.toml
├── build.rs
├── vault_license.txt
└── src/
    ├── main.rs
    └── ffi/
        ├── laminar_api.h     ← ABI header (SpatiotemporalFrame + v6.5 API)
        └── chaos_weave.c     ← C99 Lorenz core + ephemeral KDF

src/                          ← v6.4.3 OOB Integrity Edition (root package)
    main.rs
    ffi/
        laminar_api.h
        chaos_weave.c
```

---

## Core Concepts

### 1) Spatiotemporal Frame (ABI-stable, 88 bytes)

```
seq_id (u64) | x y z (f64×3) | u v w (f64×3) | fluidity (f32) | drag (f32) | divergence (f64) | payload (u8×16)
```

### 2) Lorenz Attractor Core

The C core advances Lorenz state per frame (σ=10, ρ=28, β=8.333) and uses it to mutate payload signatures and derive ephemeral session keys.

### 3) v6.5.0 — Ephemeral Key Exchange

On node startup:
1. Generate X25519 ephemeral key pair.
2. DH with peer public key → 32-byte shared secret.
3. Mix shared secret with current Lorenz state via FNV-1a KDF → 32-byte session key.
4. Encrypt all control-plane messages with ChaCha20-Poly1305 using the session key.

### 4) OOB Integrity Sync

Every 60 frames, a rolling FNV-1a digest is snapshotted and logged; nodes crossing the boundary may be quarantined if integrity diverges.

---

## Build Prerequisites

- Rust toolchain (stable)
- C compiler (gcc/clang), C99 compatible
- `cargo`

---

## Build — v6.5.0

```bash
cd yukkios_6_5_ephemeral
cargo build --release
```

Binary output:

```text
yukkios_6_5_ephemeral/target/release/yukkios_6_5_ephemeral
```

### MUSL static build

```bash
cd yukkios_6_5_ephemeral
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Binary output:

```text
yukkios_6_5_ephemeral/target/x86_64-unknown-linux-musl/release/yukkios_6_5_ephemeral
```

---

## Run

### 1) Start bootstrap server

```bash
cd yukkios_6_5_ephemeral
./target/release/yukkios_6_5_ephemeral bootstrap 127.0.0.1:9000
```

### 2) Start nodes (separate terminals)

```bash
cd yukkios_6_5_ephemeral
./target/release/yukkios_6_5_ephemeral node 127.0.0.1:9000 7001
./target/release/yukkios_6_5_ephemeral node 127.0.0.1:9000 7002
```

Each node uses:

- JSON control listener on `<p2p_port>`
- Binary tensor listener on `<p2p_port + 1000>`

---

## Interactive Node Commands

From node prompt (`YuKKiOS_6.5 >`):

| Command | Description |
|---------|-------------|
| `fleet` / `peers` | List known active nodes |
| `weave <uuid>` | Start binary laminar stream to target node |
| `msg <uuid> <text>` | Send JSON control message |
| `manifest <uuid>` | Request peer manifest |
| `browse <uuid> [path]` | List remote directory |
| `quarantine <uuid>` | Blacklist a node |
| `quarantine_check <uuid>` | Check quarantine status |
| `exit` / `quit` | Terminate node |

---

## Security Notes

- X25519 + ChaCha20-Poly1305 are used for control-plane session confidentiality in v6.5.0.
- The `ephemeral_derive_session_key` C function is a lightweight FNV-1a KDF shim; replace with HKDF-SHA256 for production use.
- The OOB hash is FNV-1a based, not a full cryptographic MAC; do not rely on it for tamper detection in adversarial settings.
- Review and harden all networking logic before production deployment.

---

## Development Notes

- `build.rs` compiles `src/ffi/chaos_weave.c` and links it (plus libm) into the Rust binary.
- `main.rs` uses async Tokio, safe argument handling (no panics on missing args), and unaligned-safe field reads for packed structs.
- `SpatiotemporalFrame` layout is identical in C (`laminar_api.h`) and Rust (`#[repr(C, packed)]`) — keep them in sync.

---

## License

This project is distributed under **GNU General Public License v3.0 (GPL-3.0)**.  
See `vault_license.txt` and repository licensing metadata for details.
