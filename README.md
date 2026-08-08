# YuKKi OS 6.6.0 Sentinel Mesh Edition

Linux-based P2P application with dependency-aware runtime behavior for Internet 3.

> **Research & Demo Software** — Not for production use. See [Security Notes](#security-notes) and `yukkios_6_6_sentinel/vault_license.txt`.

---

## Versions

| Version | Directory | Status | Highlights |
|---------|-----------|--------|------------|
| **6.6.0 Sentinel Mesh** | `yukkios_6_6_sentinel/` | **Canonical (active)** | X25519 ECDH + AEAD TCP + ChaCha20 polymorphic weave + dual-layer sentinel quarantine |
| 6.5.0 Ephemeral Mesh | `yukkios_6_5_ephemeral/` | Archived (legacy) | X25519 ECDH + ChaCha20-Poly1305 AEAD control-plane security |
| 6.4.3 OOB Integrity | (root `src/`) | Archived (legacy) | FNV-1a rolling hash, 60-frame OOB sync, node quarantine |

> **Note:** Only `yukkios_6_6_sentinel/` is actively maintained. The older version trees are preserved for historical reference only and are not supported build targets.

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
yukkios_6_6_sentinel/        ← v6.6.0 Sentinel Mesh (canonical, active)
├── Cargo.toml               ← package: yukkios_6_6_sentinel, bin: yukki_sentinel
├── build.rs                 ← cc crate compiles chaos_weave.c
├── vault_license.txt        ← GPL-3.0 + research disclaimer
└── src/
    ├── main.rs              ← Rust async runtime (Tokio)
    └── ffi/
        ├── laminar_api.h    ← ABI header (SpatiotemporalFrame + v6.6 API)
        └── chaos_weave.c    ← C99: Lorenz core, ChaCha20 weave, sentinel quarantine

yukkios_6_5_ephemeral/       ← v6.5.0 Ephemeral Mesh (archived, legacy — not a supported build target)
src/                         ← v6.4.3 OOB Integrity Edition (archived, legacy — not a supported build target)
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

