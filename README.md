# YuKKi OS v6.3.0 — Convergence Edition

**Release Date:** August 4, 2026  
**Repository:** `rakshas-oss/YuKKi-OS`  
**Tag:** `v6.3.0`

YuKKi OS v6.3.0 introduces the latest convergence architecture, unifying C-based Lorenz dynamics with Rust async networking, P2P operations, and binary frame streaming.

---

## ✨ Highlights

- Added the latest **v6.3.0 Convergence build script** (`YuKKi OS 6.3.sh`)
- Integrated **GPL-3 licensing package generation**
- Added **FFI protocol definitions** for aligned spatiotemporal tensor frames
- Added **Lorenz chaos engine core (C)** with numerical safety fallback logic
- Added **Rust convergence runtime** for:
  - WebSocket bootstrap/C2 registration
  - peer fleet synchronization
  - framed JSON messaging
  - directory browsing and file transfer
  - binary weave stream processing
- Added `build.rs` native build bridge using `cc`
- Build pipeline now produces optimized binary via `cargo build --release`

---

## 🧠 Core Architecture (v6.3)

### 1) Laminar FFI Layer
- `src/ffi/laminar_api.h`
- Defines packed/aligned `SpatiotemporalFrame` for C ↔ Rust binary compatibility

### 2) Lorenz Weave Engine (C)
- `src/ffi/chaos_weave.c`
- Implements stepwise Lorenz attractor generation and frame weaving
- Includes `isnan`/`isinf` safety resets to preserve runtime continuity

### 3) Rust Convergence Runtime
- `src/main.rs`
- Async networking with Tokio + WebSocket control
- P2P command plane + binary channel for tensor-stream exchange
- Node shell commands for fleet control, messaging, browsing, file retrieval, and weave streaming

### 4) Native Build Integration
- `build.rs`
- Compiles and links C core into Rust executable automatically

---

## 📦 Included Capabilities

- Real-time Lorenz-driven spatiotemporal frame generation
- 88-byte aligned tensor/binary transport model
- JSON-framed P2P control protocol (`msg`, `manifest`, `browse/ls`, `get`)
- Async file transfer and directory listing utilities
- Dual-port node networking model:
  - JSON control channel (P2P operations)
  - binary tensor channel (weave stream)

---

## 🛠 Build & Output

Run the release script:

```bash
bash "YuKKi OS 6.3.sh"
```

On successful compilation, the binary is generated at:

```bash
./yukkios_6_3_convergence/target/release/yukki_core_node
```

---

## ▶️ Runtime Quick Start

### Start bootstrap node
```bash
./yukki_core_node bootstrap 127.0.0.1:7000
```

### Start client node
```bash
./yukki_core_node node 127.0.0.1:7000 8001
```

(Launch additional nodes with different P2P ports.)

---

## ⚠️ Notes

- This release is shell-driven and generates the project workspace dynamically.
- Rust source references `stdin.read_line(...)`; ensure Tokio AsyncBufReadExt support is available in your environment.
- Binary frame parsing uses packed struct reads; validate architecture/ABI assumptions in heterogeneous deployments.

---

## 📜 License

Distributed under **GNU General Public License v3.0 (GPL-3.0)**.
