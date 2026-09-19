# YuKKi OS v6.7.0 — Overhauled

Experimental authenticated mesh-control service built in Rust.

## SYSTEM SNAPSHOT

```text
================================================================
             YUKKI OS v6.7.0 :: REPOSITORY SNAPSHOT
================================================================
 REPOSITORY      : rakshas-oss/YuKKi-OS
 REPOSITORY ID   : 1086802206
 DESCRIPTION     : Linux based p2p application with
                   dependency-aware RBE for Internet 3
 LANGUAGE MIX    : Rust 59.2% | Shell 32.8% | C 7.7% | Dockerfile 0.3%
================================================================
```

> **Not production-ready.** The pre-shared-key authentication and operational controls are a hardening baseline, not a substitute for an audit and managed identity system. See [Security Notes](#security-notes).

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Architecture Map](#architecture-map)
- [Heuristics Map](#heuristics-map)
- [Build Prerequisites](#build-prerequisites)
- [Quickstart](#quickstart)
- [Broker Interoperability](#broker-interoperability)
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
- ✅ **Broker client boundary** — bounded Rust TCP client for broker-first interoperability

---

## Architecture Overview

YuKKi OS v6.7.0 is a dual-plane peer-to-peer system with ephemeral session security, ADI auto-tuning, and a Rustasm WebAssembly sandbox.

### Architecture Map

```text
                         Linux based p2p application
                    dependency-aware RBE for Internet 3

  Bootstrap / Peer CLI
          |
          +-- Control plane: TCP -> X25519 + PSK -> HKDF -> AEAD JSON frames
          |                                      |
          |                                      +--> authenticated peer mesh
          |                                      +--> optional broker offload boundary
          |
          +-- Runtime services: Virtual PUF -> entropy seed
          |                      ADI tuner   -> queue depth + hardware profile
          |                      WasmSandbox -> bounded isolated execution
          |
          +-- Frame API: Rust FFI -> chaos_weave.c -> Lorenz frames (local API)
                                           |
                                           +--> epsilon failsafe -> stable reset
```

### Heuristics Map

```text
startup
  |
  +-- collect micro-timing jitter -> seed entropy
  +-- benchmark encoding + queueing
  |     |
  |     +-- queueing passes target -> queue depth 120
  |     +-- otherwise               -> queue depth 60 (default)
  |
peer connection
  |
  +-- valid length-prefixed frame (<= 64 KiB)?
  |     +-- no  -> reject
  |     +-- yes -> X25519 + shared-PSK proof -> derive directional AEAD keys
  |                                      |
  |                                      +-- authenticated -> route JSON control message
  |                                      +-- failed        -> reject
  |
frame generation
  |
  +-- divergence exceeds epsilon? -> reset Lorenz state to stable point
  +-- otherwise                   -> emit local 88-byte SpatiotemporalFrame
```

### Control Plane

JSON messages over raw TCP, framed with a 4-byte big-endian length prefix and capped at 64 KiB.
Every connection performs ephemeral **X25519** key exchange and confirms possession of a shared 32-byte pre-shared key. HKDF-SHA256 derives distinct directional **ChaCha20-Poly1305 AEAD** keys, before encrypted JSON traffic is exchanged.

### Integration Boundary

- **YuKKi-OS** is the authenticated/control-plane peer mesh: bootstrap + peer registration, fleet updates, and encrypted control messages.
- **[`rakshas-oss/overhauled`](https://github.com/rakshas-oss/overhauled)** is the external GPU placement/execution broker side of the integration boundary.
- The broker hop is a separate raw TCP client boundary in `src/broker_client.rs`; it is **not** the same authenticated transport as the peer mesh.

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
├── Cargo.toml                        ← v6.7.0 Inet3
├── build.rs
├── src/
│   ├── main.rs                       ← v6.7.0 Inet3 entry point
│   ├── adi_auto_tune.rs              ← ADI Dynamic Integration suite
│   ├── broker_client.rs              ← enterprise broker client boundary
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
│   │   ├── deploy_yukki_6_7_0_inet3.zsh
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

## Broker Interoperability

YuKKi-OS remains the authenticated Rust control plane. Interop with
[`rakshas-oss/overhauled`](https://github.com/rakshas-oss/overhauled) happens
through a distinct broker client boundary used for GPU placement/execution
requests.

### Two-plane split

- **Control plane (YuKKi-OS peer mesh):** authenticated peer sessions using
  X25519 + shared PSK + HKDF + ChaCha20-Poly1305.
- **Broker plane (YuKKi-OS -> overhauled):** one raw TCP connection per
  submission from `src/broker_client.rs`, using length-prefixed JSON and no
  YuKKi-OS end-to-end broker authentication.

### Current wire contract

- Transport: raw TCP.
- Framing: `[u32 big-endian length][UTF-8 JSON body]`.
- Connection model: one dedicated broker socket per request; timeouts and
  cancellations drop the socket instead of reusing it.
- Default limits: connect timeout `3000 ms`, whole-request timeout `5000 ms`,
  max request/response frame `65536` bytes.
- Validation before send:
  - request JSON must fit within `YUKKI_BROKER_MAX_FRAME_BYTES`
  - `task_id`, `source`, `destination`, and `kind` must be non-empty
  - `timeout_ms` must be greater than zero
  - `payload` must not be `null`
- Response validation:
  - response frame length must be greater than zero and within the configured
    max frame size
  - `task_id` must exactly match the request
  - `status` must be non-empty

#### Request body (`BrokerTask`)

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `task_id` | string | yes | caller-generated identifier |
| `source` | string | yes | logical origin, e.g. `yukki` |
| `destination` | string | yes | logical target, e.g. `overhauled` |
| `kind` | string | yes | task class such as `inference` |
| `priority` | u8 | yes | advisory priority value |
| `timeout_ms` | u32 | yes | broker-side task timeout hint; must be `> 0` |
| `payload` | JSON value | yes | task-specific body; must not be `null` |

#### Response body (`BrokerResult`)

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `task_id` | string | yes | must match the submitted request |
| `status` | string | yes | any non-empty broker status string |
| `gpu_id` | integer or null | no | optional execution placement detail |
| `execution_ms` | integer or null | no | optional execution timing |
| `result` | JSON value or null | no | optional task result payload |

Reverse-direction broker operations, if you need them, keep the same framed
JSON contract and swap the logical `source` / `destination` values.

### Security boundary

- `YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy` is **documentary**; it
  does not enable TLS or change the wire format.
- The broker hop is **not** end-to-end authenticated by YuKKi-OS today.
- For any non-loopback deployment, front the broker listener with an
  authenticated proxy, mTLS sidecar, or service mesh.
- Preserve the existing caveat: the current PSK/authenticated mesh is only a
  hardening baseline, and this repository is **not production-ready**.

Environment variables:

```bash
export YUKKI_BROKER_ENDPOINT=127.0.0.1:9000
export YUKKI_BROKER_CONNECT_TIMEOUT_MS=3000
export YUKKI_BROKER_REQUEST_TIMEOUT_MS=5000
export YUKKI_BROKER_MAX_FRAME_BYTES=65536
export YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy
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
5. All subsequent frames are AEAD-framed: `[u32 len BE][ciphertext+16-byte tag]`, with the nonce derived from direction + message counter.

### Epsilon-Threshold Failsafe

When Lorenz attractor state diverges beyond a configurable epsilon threshold, the system resets to a known stable attractor point, preventing runaway divergence from corrupting frame generation.

---

## Security Notes

- **Research/demo software**: cryptographic mechanisms are proofs-of-concept and have **not** undergone formal security audit.
- Bootstrap and peer authentication currently depend on a manually distributed pre-shared key; add managed, per-peer identities before deployment.
- Broker interoperability is isolated to the Rust client boundary and should be fronted by authenticated infrastructure if used beyond loopback or a trusted private network.
- The frame-generation API is illustrative; it is **not** an authenticated network cipher.
- Unsafe FFI calls are minimized to explicit `unsafe` blocks with documented invariants.
- Do not deploy on untrusted networks without hardening the framing protocol and adding mutual authentication.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, dual-plane architecture, FFI boundary |
| [docs/SYSADMIN_HOWTO.md](docs/SYSADMIN_HOWTO.md) | Concise Linux operator guide for build, install, service layout, broker integration, and rollback |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, known limitations, audit checklist |
| [docs/VERSIONING.md](docs/VERSIONING.md) | Version history (archived) |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Build, bootstrap setup, node configuration, commands |
| [docs/API.md](docs/API.md) | FFI reference, C headers, function signatures |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors, debug logging, performance tuning |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Release notes |
| [docs/RELEASE_v6.7.0.md](docs/RELEASE_v6.7.0.md) | v6.7.0 release documentation |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style, testing, PR process, security reporting |

---

## License

This project is distributed under **GNU General Public License v3.0 (GPL-3.0)**.  
See [`docs/licensing/vault_license.txt`](docs/licensing/vault_license.txt) and `LICENSE` for details.
