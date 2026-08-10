# YuKKi OS v6.6.4 — Apex Synthesis Edition

Linux-based P2P application with dependency-aware runtime behavior for Internet 3.

> **Research & Demo Software** — Not for production use. See [Security Notes](#security-notes) and [`docs/licensing/vault_license.txt`](docs/licensing/vault_license.txt).

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
- ✅ **Rustasm WebAssembly Sandbox** (Wasmtime) — isolated execution environment
- ✅ **Explicit volatile memory wiping** with `zeroize` crate
- ✅ **Epsilon-Threshold Failsafe** for Lorenz attractor recovery
- ✅ **X25519 ECDH** ephemeral key exchange + **ChaCha20-Poly1305 AEAD** control plane
- ✅ **Polymorphic payload weave** — attractor-bound cipher stream

---

## Architecture Overview

YuKKi OS v6.6.4 is a dual-plane peer-to-peer system with ephemeral session security, ADI auto-tuning, and a Rustasm WebAssembly sandbox.

### Control Plane

JSON messages over raw TCP, framed with a 4-byte big-endian length prefix.
Every message is encrypted with **ChaCha20-Poly1305 AEAD** using a session key derived from an **X25519 Diffie-Hellman** exchange (one ephemeral key-pair per session, never persisted).

### Data Plane

Binary `SpatiotemporalFrame` (88 bytes) stream produced by the **Lorenz attractor** C core (`src/ffi/chaos_weave.c`).
Frames carry a 16-byte payload slot, a fluidity/drag coefficient pair, and a divergence scalar.

### ADI Auto-Tuning Suite

The `ADIAutoTuner` (`src/adi_auto_tune.rs`) benchmarks encoding throughput and queuing efficiency at startup to select the optimal queue depth and hardware profile for the current environment.

### Rustasm WebAssembly Sandbox

The `WasmSandbox` (`src/wasm_sandbox.rs`) wraps a Wasmtime engine to execute untrusted modules in isolation, returning results without exposing host memory.

### Virtual PUF (Micro-Timing Anchor)

High-resolution timing measurements taken at boot provide a device-unique entropy contribution, seeding the random state with environmental jitter that is not predictable across hardware.

Here is the architecture formatted specifically for a GitHub `README.md` file. The structure uses blockquotes for the marque/brand callouts, a raw code block to preserve the exact spacing of your ASCII schematic, and clean hierarchical headers for the security heuristics to ensure high scannability.

---

# YuKKi OS v6.6.4 [APEX SYNTHESIS]

> **© 2076 RIU (Rakshas International Unlimited)**
> **Marque : oldies | Brand : oldies**

---

## 🏛️ Architectural Schematic

Below is the complete structural operation, memory flow, and active security heuristic map for the YuKKi OS v6.6.4 architecture.

```text
========================================================================================
             YuKKi OS v6.6.4 [APEX SYNTHESIS] - ARCHITECTURAL SCHEMATIC
                   (C) 2076 RIU | MARQUE : oldies | BRAND : oldies
========================================================================================
 
                            [ P2P MESH TOPOLOGY ]
                                      |
         .----------------------------+----------------------------.
         |                                                         |
 [ TCP CONTROL PLANE (Port X) ]                    [ UDP DATA PLANE (Port X+1000) ]
         |                                                         |
+------------------------------+                  +------------------------------+
| 1. DUAL-LAYER FIREWALL       |                  | 1. ADI AUTO-TUNING SUITE     |
|    [!] Heuristic: Check IP   |                  |    [!] Heuristic: 64-bit     |
|    blacklist PRE-handshake.  |                  |    Alignment & Batch Depth   |
|    Drop socket instantly if  |                  |    (Short opcodes bypassed)  |
|    quarantined.              |                  +------------------------------+
+------------------------------+                                   |
         | (Clean IP)                                              v
         v                                        +------------------------------+
+------------------------------+                  | 2. 88-BYTE FRAME ACQUISITION |
| 2. X25519 ECDH HANDSHAKE     |                  |    - seq_id, x, y, z, u, v, w|
|    - Ephemeral Key Exchange  |                  |    - fluidity, drag, div.    |
|    - Derives Session Key     |                  |    - 16-byte Payload Chunk   |
+------------------------------+                  +------------------------------+
         |                                                         |
         v                                                         v
+------------------------------+                  +------------------------------+
| 3. AEAD CHACHA20-POLY1305    |                  | 3. POLYMORPHIC CHACHA20 (C99)|
|    - Decrypts JSON control   |                  |    - Lorenz 6D Attractor     |
|    messages (OOB Sync)       |                  |    - Virtual PUF Micro-timing|
|    [!] Heuristic: MAC fail   |                  |    [!] Heuristic: Epsilon    |
|    triggers Auto-Quarantine. |                  |    Failsafe blocks zero-state|
+------------------------------+                  +------------------------------+
         |                                                         |
         | (BLAKE3 Hash / Anchors)                                 | (16B Decrypted Chunk)
         '----------------------------.----------------------------'
                                      |
                                      v
                       +------------------------------+
                       | 4. OUT-OF-BAND VALIDATION    |
                       |    - Accumulates 60 frames   |
                       |    - Compares C99 payload    |
                       |      hash against TCP hash.  |
                       |    [!] Heuristic: Mismatch   |
                       |    triggers Auto-Quarantine. |
                       +------------------------------+
                                      |
                                      | (Verified Wasm Bytecode)
                                      v
                       +------------------------------+
                       | 5. RUSTASM CIVILIAN SANDBOX  |
                       |    - Wasmtime Execution      |
                       |    - Max Stack: 512 KB       |
                       |    [!] Heuristic: Epoch      |
                       |    interruption traps loops  |
                       |    and buffer overflows.     |
                       +------------------------------+
                                      |
                                      v
========================================================================================
[!] TERMINAL HEURISTIC: EXPLICIT MEMORY TEARDOWN
----------------------------------------------------------------------------------------
 -> C99 `secure_wipe()`    :: Annihilates ChaCha20 matrices & Lorenz permutation states
 -> Rust `buf.zeroize()`   :: Flushes execution buffer & drops X25519 ephemeral keys
 -> GOAL                   :: Defeats /proc/kcore RAM scraping & cold-boot attacks
========================================================================================

```

---

## 🛡️ Active Security Heuristics Breakdown

### 1. The 64-Bit ADI Hardware Clamp

* **Trigger:** Network enqueue and serialization.
* **Action:** Short opcodes are utterly bypassed. By clamping the `SpatiotemporalFrame` strictly to 88 bytes with zero padding using `#pragma pack(push, 1)`, the architecture prevents pipeline stalls and forces the classical OS to handle data in perfect 64-bit native word segments, mitigating memory fragmentation.

### 2. The Epsilon-Threshold Failsafe

* **Trigger:** Lorenz *x*, *y*, *z* coordinates falling below the `1e-9` threshold.
* **Action:** If adversarial fuzzing forces the chaotic manifold toward a degenerate zero-state (which would stop the polymorphic keys from rotating), the `fabs()` heuristic violently injects baseline entropy (`0.1`) back into the *x*-axis, preserving forward secrecy.

### 3. The Virtual PUF CPU-Jitter Anchor

* **Trigger:** Node initialization.
* **Action:** Binds the base ChaCha20 keystream to the microscopic contextual time-drifts (jitter) of the local host CPU (`clock_gettime(CLOCK_MONOTONIC)`). If the VM is cloned or memory is scraped to spoof the node, the micro-timing changes, the keystream breaks, and the network drops the imposter.

### 4. The Sentinel Auto-Quarantine

* **Trigger:** Poly1305 MAC failure (TCP bit-flipping) OR BLAKE3 OOB Hash Mismatch (UDP payload forgery).
* **Action:** Instantly burns the peer's UUID from the active fleet registry and drops their IP address into the Layer-1 Pre-Handshake Firewall, terminating all future connections in microseconds before X25519 math can waste CPU cycles.

### 5. The Rustasm Epoch Interruption

* **Trigger:** Civilian execution layer logic.
* **Action:** Validated payloads are run inside a rigid `wasmtime` sandbox with a 512KB limit. If a decrypted payload attempts to poison the host via an infinite loop or buffer overflow, the epoch interrupt instantly panics the Wasm instance, preserving the Linux kernel and the cryptographic core.

---

## Repository Structure

```text
YuKKi-OS/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── Cargo.toml                        ← v6.6.4 Apex Synthesis
├── build.rs
├── src/
│   ├── main.rs                       ← v6.6.4 Apex entry point
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
│   │   ├── deploy_yukki_6_6_4_apex.zsh
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
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
```

### Run — Peer node

Connect a peer node to the bootstrap:

```bash
./target/release/yukki_core_node node 127.0.0.1:7660 9999
```

---

## Command Reference

From the interactive prompt (`>`):

| Command | Description |
|---------|-------------|
| `fleet peers` | List all currently connected peer nodes |
| `msg <to> <text>` | Send an AEAD-encrypted `FluidMessage` to a peer (by node-id or `all`) |
| `weave <data>` | Announce a polymorphic-woven payload (`WeaveAnnounce`) |
| `exit` / `quit` | Shut down the node |

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
- The KDF used is intentionally minimal; replace with **HKDF-SHA256** before any production use.
- The polymorphic weave (`chacha_weave_payload`) is illustrative; it is **not** an authenticated cipher — replay and mutation attacks are possible.
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
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style, testing, PR process, security reporting |

---

## License

This project is distributed under **GNU General Public License v3.0 (GPL-3.0)**.  
See [`docs/licensing/vault_license.txt`](docs/licensing/vault_license.txt) and `LICENSE` for details.
