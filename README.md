# YuKKi OS v6.6.6 — Inet3 Edition

Experimental authenticated mesh-control service built in Rust.

> **Not production-ready.** The pre-shared-key authentication and operational controls are a hardening baseline, not a substitute for an audit and managed identity system. See [Security Notes](#security-notes).

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Build Prerequisites](#build-prerequisites)
- [Quickstart](#quickstart)
- [Command Reference](#command-reference)
- [Core Concepts](#core-concepts)
- [Security Notes](#security-notes)
- [Documentation](#documentation)
- [License](#license)

---

## Features

- ✅ **ADI Dynamic Integration** auto-tuning suite — runtime queue depth and hardware profile optimization
- ✅ **Virtual PUF** micro-timing anchor for entropy seeding
- ✅ **Rustasm WebAssembly Sandbox** (Wasmtime) — fuel- and memory-bounded isolated execution API
- ✅ **Explicit volatile memory wiping** with `zeroize` crate
- ✅ **Epsilon-Threshold Failsafe** for Lorenz attractor recovery
- ✅ **X25519 ECDH** ephemeral key exchange + **ChaCha20-Poly1305 AEAD** control plane
- ✅ **Polymorphic payload weave** — attractor-bound cipher stream

---

## Architecture Overview

YuKKi OS v6.6.6 is a dual-plane peer-to-peer system with ephemeral session security, ADI auto-tuning, and a Rustasm WebAssembly sandbox.

### Control Plane

JSON messages over raw TCP, framed with a 4-byte big-endian length prefix and capped at 64 KiB.
Every connection performs ephemeral **X25519** key exchange and confirms possession of a shared 32-byte pre-shared key. HKDF-SHA256 derives distinct directional **ChaCha20-Poly1305 AEAD** keys, binding protocol context as associated data.

### Frame Generation API

`SpatiotemporalFrame` is an 88-byte FFI structure produced by the Lorenz C core (`src/ffi/chaos_weave.c`). It is not exposed as a network data plane.

### ADI Auto-Tuning Suite

The `ADIAutoTuner` (`src/adi_auto_tune.rs`) benchmarks encoding throughput and queuing efficiency at startup to select the optimal queue depth and hardware profile for the current environment.

### Rustasm WebAssembly Sandbox

The `WasmSandbox` (`src/wasm_sandbox.rs`) wraps a Wasmtime engine to execute untrusted modules in isolation, returning results without exposing host memory.

### Virtual PUF (Micro-Timing Anchor)

High-resolution timing measurements taken at boot provide a device-unique entropy contribution, seeding the random state with environmental jitter that is not predictable across hardware.

---

## Repository Structure

```text
YuKKi-OS/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── Cargo.toml                        ← v6.6.6 Inet3
├── build.rs
├── src/
│   ├── main.rs                       ← v6.6.6 Inet3 entry point
│   ├── adi_auto_tune.rs              ← ADI Dynamic Integration suite
│   ├── wasm_sandbox.rs               ← Rustasm WebAssembly sandbox
│   └── ffi/
│       ├── laminar_api.h
│       └── chaos_weave.c
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── CHANGELOG.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── TROUBLESHOOTING.md
│   ├── VERSIONING.md                 ← version history (archived)
│   └── licensing/
│       └── vault_license.txt
├── scripts/
│   ├── deploy/
│   │   ├── deploy_yukki_6_6_6_inet3.zsh
│   │   └── README.md
│   └── legacy/
│       ├── YuKKi_OS_6.4.3_OOB-Integrity.sh
│       ├── YuKKi_OS_6.4_Interim-Crypt.sh
│       └── DEPRECATED.md
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature_request.md
    └── pull_request_template.md
```

---

## Build Prerequisites

- Rust stable toolchain (`rustup toolchain install stable`)
- C99 compiler: `gcc` or `clang`
- `cargo` (included with rustup)

---

## Quickstart

### Build

```bash
cargo build --release
```

Binary output: `target/release/yukki_core_node`

#### MUSL static build (optional)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Run — Bootstrap node

Start the bootstrap server (listens for inbound node connections):

```bash
export YUKKI_PSK_HEX="$(openssl rand -hex 32)"
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
```

### Run — Peer node

Connect a peer node to the bootstrap:

```bash
./target/release/yukki_core_node node 127.0.0.1:7660 127.0.0.1:9999
```

---

## Command Reference

From the interactive prompt (`>`):

| Command | Description |
|---------|-------------|
| `bootstrap <bind-address>` | Start a 128-connection authenticated bootstrap service |
| `node <bootstrap-address> <advertised-address>` | Register an authenticated node |
| Ctrl-C | Gracefully terminate the current process |

---

## Core Concepts

### Spatiotemporal Frame (ABI-stable, 88 bytes)

```
seq_id (u64) | x y z (f64×3) | u v w (f64×3) | fluidity (f32) | drag (f32) | divergence (f64) | payload (u8×16)
```

The `#[repr(C, packed)]` Rust struct and the `#pragma pack(push,1)` C struct are kept byte-identical across FFI boundaries.

### X25519 Handshake Protocol

1. Node A sends its X25519 ephemeral public key (32 bytes raw) over TCP.
2. Node B responds with its own public key.
3. Both sides compute `shared = ECDH(my_secret, peer_pub)`.
4. A lightweight KDF produces the 32-byte session key.
5. All subsequent frames are AEAD-framed: `[u32 len BE][12-byte nonce][ciphertext+16-byte tag]`.

### Epsilon-Threshold Failsafe

When Lorenz attractor state diverges beyond a configurable epsilon threshold, the system resets to a known stable attractor point, preventing runaway divergence from corrupting frame generation.

---

## Security Notes

- **Research/demo software**: cryptographic mechanisms are proofs-of-concept and have **not** undergone formal security audit.
- Bootstrap and peer authentication currently depend on a manually distributed pre-shared key; add managed, per-peer identities before deployment.
- The frame-generation API is illustrative; it is **not** an authenticated network cipher.
- Unsafe FFI calls are minimized to explicit `unsafe` blocks with documented invariants.
- Do not deploy on untrusted networks without hardening the framing protocol and adding mutual authentication.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, dual-plane architecture, FFI boundary |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, known limitations, audit checklist |
| [docs/VERSIONING.md](docs/VERSIONING.md) | Version history (archived) |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Build, bootstrap setup, node configuration, commands |
| [docs/API.md](docs/API.md) | FFI reference, C headers, function signatures |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors, debug logging, performance tuning |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Release notes |
| [docs/RELEASE_v6.6.6.md](docs/RELEASE_v6.6.6.md) | Branch v6.6.6 release documentation |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style, testing, PR process, security reporting |

---

## License

This project is distributed under **GNU General Public License v3.0 (GPL-3.0)**.  
See [`docs/licensing/vault_license.txt`](docs/licensing/vault_license.txt) and `LICENSE` for details.
