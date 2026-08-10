# YuKKi OS 6.6.0 Sentinel Mesh Edition

Linux-based P2P application with dependency-aware runtime behavior for Internet 3.

> **Research & Demo Software** — Not for production use. See [Security Notes](#security-notes) and [`docs/licensing/vault_license.txt`](docs/licensing/vault_license.txt).

---

## Table of Contents

- [Versions](#versions)
- [Architecture Overview](#architecture-overview--v660-sentinel-mesh)
- [Repository Structure](#repository-structure)
- [Build Prerequisites](#build-prerequisites)
- [Quickstart](#quickstart)
- [Command Reference](#command-reference)
- [Core Concepts](#core-concepts)
- [Security Notes](#security-notes)
- [Documentation](#documentation)
- [License](#license)

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, dual-plane architecture, FFI boundary |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, known limitations, audit checklist |
| [docs/VERSIONING.md](docs/VERSIONING.md) | Version strategy, feature matrix, migration guide |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Build, bootstrap setup, node configuration, commands |
| [docs/API.md](docs/API.md) | FFI reference, C headers, function signatures, usage examples |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors, debug logging, performance tuning |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Per-version feature summaries |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style, testing, PR process, security reporting |

---

## Versions

| Version | Directory | Highlights |
|---------|-----------|------------|
| **6.6.0 Sentinel Mesh** | `yukkios_6_6_sentinel/` | X25519 ECDH + AEAD TCP + ChaCha20 polymorphic weave + dual-layer sentinel quarantine |
| 6.5.0 Ephemeral Mesh | `yukkios_6_5_ephemeral/` | X25519 ECDH + ChaCha20-Poly1305 AEAD control-plane security |
| 6.4.3 OOB Integrity | (root `src/`) | FNV-1a rolling hash, 60-frame OOB sync, node quarantine |

---

## Architecture Overview — v6.6.0 Sentinel Mesh

YuKKi OS 6.6.0 is a dual-plane peer-to-peer system with ephemeral session security and sentinel quarantine.

### Control Plane

JSON messages over raw TCP, framed with a 4-byte big-endian length prefix.  
Every message is encrypted with **ChaCha20-Poly1305 AEAD** using a session key derived from an **X25519 Diffie-Hellman** exchange (one ephemeral key-pair per session, never persisted).

### Data Plane

Binary `SpatiotemporalFrame` (88 bytes) stream produced by the **Lorenz attractor** C core (`chaos_weave.c`).  
Frames carry a 16-byte payload slot, a fluidity/drag coefficient pair, and a divergence scalar derived from Lorenz state.

### Integrity Sync — Sentinel Quarantine

The C layer maintains a dual-layer quarantine registry (up to 256 entries):

| Level | Name | Trigger | Effect |
|-------|------|---------|--------|
| 1 | Soft quarantine | Frame-hash mismatch detected | Messages from node are logged and dropped |
| 2 | Hard quarantine | Escalation (re-quarantine of level-1 node) | Connection rejected at handshake |

Rust code calls `sentinel_quarantine_node` / `sentinel_release_node` via FFI.

### Polymorphic Payload Weave

`chacha_weave_payload` (C99) XORs arbitrary plaintext against a ChaCha20 keystream whose key is mixed with the current Lorenz attractor state, producing a **session-unique, attractor-bound cipher stream**.

---

## Repository Structure

```text
YuKKi-OS/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── Cargo.toml                   ← root package (v6.4.3 OOB Integrity)
├── build.rs
├── src/                         ← v6.4.3 OOB Integrity Edition
│   ├── main.rs
│   └── ffi/
│       ├── laminar_api.h
│       └── chaos_weave.c
├── yukkios_6_5_ephemeral/       ← v6.5.0 Ephemeral Mesh
├── yukkios_6_6_sentinel/        ← v6.6.0 Sentinel Mesh (current)
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── main.rs
│       └── ffi/
│           ├── laminar_api.h
│           └── chaos_weave.c
├── scripts/
│   ├── deploy/
│   │   └── deploy_yukki_6_6_4_apex.zsh   ← v6.6.4 Apex deployment script
│   └── legacy/                            ← archived v6.4.x scripts (deprecated)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── CHANGELOG.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── TROUBLESHOOTING.md
│   ├── VERSIONING.md
│   └── licensing/
│       └── vault_license.txt
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
cd yukkios_6_6_sentinel
cargo build --release
```

Binary output: `yukkios_6_6_sentinel/target/release/yukki_sentinel`

#### MUSL static build (optional)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Run — Bootstrap node

Start the bootstrap server (listens for inbound node connections):

```bash
cd yukkios_6_6_sentinel
./target/release/yukki_sentinel bootstrap 0.0.0.0:7660
```

### Run — Peer node

Connect a peer node to the bootstrap:

```bash
cd yukkios_6_6_sentinel
./target/release/yukki_sentinel node 127.0.0.1:7660
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

### Examples

```
> fleet peers
  node-3f7a2... @ 127.0.0.1:49821 [q=0]

> msg node-3f7a2 hello sentinel mesh
[node-…] msg from node-3f7a2 [seq=1]: hello sentinel mesh

> weave deadbeef
[node-…] weave from … [seq=2]: <hex>

> exit
Exiting...
```

---

## Core Concepts

### Spatiotemporal Frame (ABI-stable, 88 bytes)

```
seq_id (u64) | x y z (f64×3) | u v w (f64×3) | fluidity (f32) | drag (f32) | divergence (f64) | payload (u8×16)
```

The `#[repr(C, packed)]` Rust struct and the `#pragma pack(push,1)` C struct are kept byte-identical.

### X25519 Handshake Protocol

1. Node A sends its X25519 ephemeral public key (32 bytes raw) over TCP.
2. Node B responds with its own public key.
3. Both sides compute `shared = ECDH(my_secret, peer_pub)`.
4. A lightweight KDF (XOR + rotate with a domain separator) produces the 32-byte session key.
5. All subsequent frames are AEAD-framed: `[u32 len BE][12-byte nonce][ciphertext+16-byte tag]`.

---

## Security Notes

- **Research/demo software**: the sentinel quarantine and cryptographic mechanisms are proofs-of-concept and have **not** undergone formal security audit.
- The KDF used (`shared_secret XOR domain_separator + rotate`) is intentionally minimal; replace with **HKDF-SHA256** before any production use.
- The polymorphic weave (`chacha_weave_payload`) is illustrative; it is **not** an authenticated cipher — replay and mutation attacks are possible.
- Unsafe FFI calls are minimized to explicit `unsafe` blocks with documented invariants (null pointer guards in C, `CString` bounds checks in Rust).
- Do not deploy on untrusted networks without hardening the framing protocol and adding mutual authentication.

---

## License

This project is distributed under **GNU General Public License v3.0 (GPL-3.0)**.  
See `yukkios_6_6_sentinel/vault_license.txt` and repository licensing metadata for details.

