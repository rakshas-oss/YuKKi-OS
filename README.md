# YuKKi OS 6.4.4 — Polymorphic & Self-Healing Mesh

Linux-based P2P application with dependency-aware runtime behavior for Internet 3.

## Overview

YuKKi OS 6.4.4 is a dual-plane peer-to-peer system:

- **Control Plane (JSON over TCP/WebSocket)** for peer registry, signaling, and out-of-band integrity sync.
- **Data Plane (Binary Tensor Stream)** for high-frequency `SpatiotemporalFrame` transport.
- **C FFI Core** for Lorenz-state evolution, polymorphic ChaCha20-style payload binding, and batch integrity signaling.
- **Rust Node Runtime** for networking, orchestration, and node lifecycle.

> Repository language composition: Rust, C, and Shell.

---

## Repository Structure

```text
yukkios_6_4_4_polymorphic/
├── Cargo.toml
├── build.rs
├── vault_license.txt
└── src/
    ├── main.rs
    └── ffi/
        ├── laminar_api.h
        └── chaos_weave.c
```

---

## Core Concepts

### 1) Spatiotemporal Frame

A packed frame exchanged over the data plane:

- Sequence ID
- Spatial coordinates (`x, y, z`)
- Drift vector (`u, v, w`)
- Fluidity/drag scalars
- Divergence
- 16-byte payload segment

### 2) Chaotic State Evolution

The C core maintains Lorenz attractor state and advances per frame.  
That state is used to mutate keystream input and produce polymorphic payload signatures.

### 3) Out-of-Band Integrity Sync

Every 60 frames, a rolling integrity digest is generated and shipped over the control plane with anchor coordinates (`x, y, z`) + sequence pointer for resync behavior.

---

## Build Prerequisites

- Linux/macOS shell
- Rust toolchain (stable)
- C compiler (gcc/clang) compatible with C99
- `cargo`

For static legacy target:
- `x86_64-unknown-linux-musl` toolchain target installed

---

## Build

From repo root (where `yukkios_6_4_4_polymorphic/` exists):

```bash
cd yukkios_6_4_4_polymorphic
cargo build --release
```

Binary output:

```text
target/release/yukkios_6_4_4_polymorphic
```

### LEGACY_MODE / MUSL static build

```bash
cd yukkios_6_4_4_polymorphic
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Binary output:

```text
target/x86_64-unknown-linux-musl/release/yukkios_6_4_4_polymorphic
```

---

## Run

## 1) Start bootstrap server

```bash
./target/release/yukkios_6_4_4_polymorphic bootstrap 127.0.0.1:9000
```

## 2) Start nodes (separate terminals)

```bash
./target/release/yukkios_6_4_4_polymorphic node 127.0.0.1:9000 7001
./target/release/yukkios_6_4_4_polymorphic node 127.0.0.1:9000 7002
```

Each node uses:

- JSON control listener on `<p2p_port>`
- Binary listener on `<p2p_port + 1000>`

---

## Interactive Node Commands

From node prompt:

- `fleet` / `peers` — list known active nodes
- `weave <uuid>` — start binary laminar stream to target node
- `exit` / `quit` — terminate node process

---

## Security & Integrity Notes

- Quarantine behavior is demonstrated through special control-plane markers.
- Resync path uses anchor coordinates to realign Lorenz state via FFI.
- The included hash routine in the C file is a lightweight shim for batch signaling, not a full cryptographic BLAKE3 implementation.
- Review and harden all cryptographic and networking logic before production use.

---

## Development Notes

- `build.rs` compiles `src/ffi/chaos_weave.c` and links it into the Rust binary.
- `main.rs` uses async Tokio runtime, WebSocket bootstrap sync, framed TCP messaging, and FFI calls into the C engine.
- FFI packet layout must remain ABI-compatible between Rust and C definitions.

---

## License

This project is distributed under **GNU General Public License v3.0 (GPL-3.0)**.  
See `vault_license.txt` and repository licensing metadata for details.
