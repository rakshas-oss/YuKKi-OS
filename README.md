# YuKKi OS v6.4.0 — Interim-Crypt Edition

**Release Date:** August 8, 2026  
**Repository:** `rakshas-oss/YuKKi-OS`  
**Tag:** `v6.4.0`

YuKKi OS v6.4.0 promotes the generated v6.3 sources into a persistent Rust/C repository layout and adds an opt-in Interim-Crypt payload layer on top of the existing Lorenz-driven mesh runtime.

---

## ✨ Highlights

- Persistent tracked source tree for Rust runtime and C FFI components
- `src/crypto.rs` for Pauli/Clifford-inspired encryption bindings
- `src/ffi/crypt_layer.c` for mutex-protected bit-level transforms
- Existing P2P messaging, file transfer, browse, manifest, and weave streaming preserved
- Backward-compatible framing: plaintext legacy payloads still decode when encryption is disabled

---

## 🧠 Core Architecture (v6.4)

### 1) Rust Runtime
- `src/main.rs`
- Tokio async networking for bootstrap, P2P control, binary weave streaming, browse, and file transfer
- Optional encrypted JSON payload transport via `send_p2p_message()` / `handle_p2p_connection()`

### 2) Crypto Layer
- `src/crypto.rs`
- Wraps encrypted payloads with a versioned header and per-message nonce
- Uses the native crypt layer for reversible payload transforms
- Enable with `YUKKI_ENABLE_ENCRYPTION=1`

### 3) Native FFI
- `src/ffi/laminar_api.h`
- `src/ffi/chaos_weave.c`
- `src/ffi/crypt_layer.c`
- Lorenz frame generation remains intact, with encrypted frame payload blocks derived from the sequence number

### 4) Build Integration
- `build.rs`
- Compiles both native C units and links `libm`/`pthread`
- `YuKKi_OS_6.4_Interim-Crypt.sh` remains as the release-oriented build orchestrator

---

## 📦 Included Capabilities

- Real-time Lorenz-driven spatiotemporal frame generation
- 88-byte aligned tensor/binary transport model
- JSON-framed P2P control protocol (`msg`, `manifest`, `browse/ls`, `get`)
- Async file transfer and directory listing utilities
- Dual-port node networking model:
  - JSON control channel
  - binary tensor channel
- Opt-in encrypted control-plane payloads with legacy coexistence

---

## 🛠 Build & Output

Build directly from the repository root:

```bash
cargo build --release
```

Or use the orchestrator:

```bash
./YuKKi_OS_6.4_Interim-Crypt.sh
```

Binary output:

```bash
./target/release/yukki_core_node
```

---

## ▶️ Runtime Quick Start

### Start bootstrap node
```bash
./target/release/yukki_core_node bootstrap 127.0.0.1:7000
```

### Start client node
```bash
./target/release/yukki_core_node node 127.0.0.1:7000 8001
```

### Enable Interim-Crypt payload protection
```bash
YUKKI_ENABLE_ENCRYPTION=1 ./target/release/yukki_core_node node 127.0.0.1:7000 8001
```

---

## 🔐 Security Model Notes

- Encryption is opt-in so legacy nodes can continue exchanging plaintext framed JSON payloads.
- Encrypted payloads are tagged with a one-time nonce and transformed through the native Clifford/Pauli-inspired layer configured from the Lorenz parameters.
- Binary weave transport and file operations remain operational without changing the command set.

---

## 📜 License

Distributed under **GNU General Public License v3.0 (GPL-3.0)** for the v6.4 release.
