# YuKKi OS v6.4.2 — Interim-Crypt Edition

**Release Date:** August 8, 2026  
**Repository:** `rakshas-oss/YuKKi-OS`  
**Branch:** `main`  
**License:** GNU General Public License v3.0 (GPL-3.0)  
**Architect:** Aditya Muralidhar (Rakshas International Unlimited)

YuKKi OS v6.4.2 **Interim-Crypt Edition** advances the spatiotemporal weaving architecture with a hardened payload-binding path powered by **ChaCha20-derived keystream encryption**, while preserving the existing Lorenz-driven tensor model and distributed runtime behavior.

---

## ✨ Key Features

### 🔐 ChaCha20 Payload Binding (NEW in v6.4.2)
- **ChaCha20 ARX Core** - 20-round keystream block generation using quarter-round operations
- **Sequence-Bound Nonce Derivation** - Packet `seq_id` maps into nonce words for deterministic per-sequence payload transformation
- **Secure Slab Descriptor** - `SecureQuantumSlab` stores encrypted signature and active basis metadata
- **16-Byte Signature Encryption** - First keystream segment binds payload bytes into frame payload space

### 🌀 6D Lorenz-Weave Engine
- **Spatiotemporal Frame Generation** - Real-time chaos-driven tensor packet generation
- **88-Byte Hyper-Aligned Packets** - Binary-compatible tensor frames with strict memory alignment
- **6D Velocity Drift** - Coupled spatial coordinates (x,y,z) with velocity vectors (u,v,w)
- **Fluidity Metric** - Sigmoid-normalized flow coherence calculation

### 🌐 P2P Distributed Architecture
- **Bootstrap Server** - WebSocket-based C2 node registry with fleet synchronization
- **Dual-Port Networking** - Separate JSON control and binary tensor channels
- **Async I/O Pipeline** - Full Tokio runtime with zero-copy file transfers
- **Directory Browsing & File Transfer** - Secure P2P filesystem operations across nodes

### ⚡ Interactive Node Shell
- `fleet`/`peers` - View active node topology and peer registry
- `msg <uuid> <text>` - Send JSON-framed messages to peers
- `manifest <uuid>` - Exchange project manifests between nodes
- `browse/ls <uuid> [path]` - Remote directory listing
- `get <uuid> <remote_path> <local_path>` - Pull files from peer nodes
- `weave <uuid>` - Establish binary tensor stream with target node
- `exit`/`quit` - Graceful shutdown

---

## 🏗️ Architecture Overview

### Layer 1: FFI Bridge (Legacy-Safe C99)
```
src/ffi/
├── laminar_api.h        ← Binary tensor packet definitions
└── chaos_weave.c        ← Lorenz engine + ChaCha20 payload binding core
```

**Key Components:**
- **SpatiotemporalFrame** - 88-byte packed struct (seq_id, spatial/velocity coords, fluidity, drag, payload)
- **SecureQuantumSlab** - Descriptor with encrypted signature and active basis flag
- **chacha20_block()** - Keystream generator using constant-time ARX quarter-round composition
- **secure_chacha20_bind()** - 16-byte payload binding via XOR against generated keystream bytes
- **generate_lorenz_step()** - Differential equation solver with numerical stability safeguards

### Layer 2: Rust Async Runtime
```
src/main.rs
├── ChaosController          ← FFI frame extraction wrapper
├── run_c2_bootstrap()       ← WebSocket server for peer registration
├── run_p2p_listener()       ← JSON message protocol handler
├── run_binary_listener()    ← Binary tensor stream processor
└── run_client_node()        ← Interactive shell + fleet orchestration
```

### Layer 3: Build Integration
```
build.rs                    ← Auto-compiles chaos_weave.c with C99 strict mode
Cargo.toml                  ← Rust dependency manifest
```

---

## 📊 Technical Specifications

| Specification | Value |
|---|---|
| **Tensor Frame Size** | 88 bytes (hyper-aligned) |
| **Sequence Counter** | 64-bit unsigned (u64) |
| **Spatial Dimensions** | 3D (x, y, z as f64) |
| **Velocity Dimensions** | 3D (u, v, w as f64) |
| **Encrypted Payload** | 16 bytes (ChaCha20 keystream-bound) |
| **Fluidity Metric** | 32-bit float (sigmoid normalized) |
| **Default Lorenz Params** | σ=10.0, ρ=28.0, β≈8.333 |
| **Time Step (dt)** | 0.005 seconds |
| **Weave Stream Rate** | 100 frames × 15ms intervals = ~1.5s session |

---

## 🚀 Building & Deployment

### Prerequisites
- **Rust 1.70+** with Cargo
- **C99 compatible compiler** (gcc/clang)
- **Linux/macOS** (Unix-like environment)
- Optional: **MUSL target** for fully static binaries

### Build (Standard Release)
```bash
cargo build --release
```

Binary output:
```
./target/release/yukkios_6_4_interim
```

### Genesis Script (Hardened, Same Features)
```bash
zsh ./YuKKi_OS_6.4_Interim-Crypt.sh
```

### Build (Legacy Static - MUSL)
```bash
export LEGACY_MODE=1
cargo build --release --target=x86_64-unknown-linux-musl
```

Binary output:
```
./target/x86_64-unknown-linux-musl/release/yukkios_6_4_interim
```

---

## ▶️ Runtime Usage

### 1. Start Bootstrap Coordinator Node
```bash
./yukkios_6_4_interim bootstrap 127.0.0.1:7000
```

### 2. Start Client Nodes (in separate terminals)
```bash
# Node 1
./yukkios_6_4_interim node 127.0.0.1:7000 8001

# Node 2
./yukkios_6_4_interim node 127.0.0.1:7000 8002

# Node 3
./yukkios_6_4_interim node 127.0.0.1:7000 8003
```

### 3. Interactive Commands
- `fleet` / `peers`
- `msg <uuid> <text>`
- `manifest <uuid>`
- `browse|ls <uuid> [path]`
- `get <uuid> <remote_path> <local_path>`
- `weave <uuid>`
- `exit` / `quit`

---

## 🔐 Security & Cryptography Notes

### ChaCha20 Binding Model (v6.4.2)
The payload binding path in `src/ffi/chaos_weave.c` now uses a ChaCha20-style keystream workflow:

1. **State Setup** - Sigma constants + 256-bit mesh key + sequence-derived nonce
2. **20-Round Mixing** - Column and diagonal quarter-round cycles
3. **Keystream Finalization** - Working state folded back into initial state
4. **Payload Binding** - First 16 keystream bytes XOR against payload

This upgrade replaces the prior fixed XOR signature approach with a per-sequence transformed signature model and improves variability of payload protection across frame sequences.

---

## 📜 License

**GNU General Public License v3.0 (GPL-3.0)**

See `vault_license.txt` for complete licensing text.

---

## 👤 Authors & Contributors

**Primary Architect:** Aditya Muralidhar  
**Organization:** Rakshas International Unlimited  
**Repository:** https://github.com/rakshas-oss/YuKKi-OS

---

## 🔗 Quick Links

- **Latest Release:** https://github.com/rakshas-oss/YuKKi-OS/tree/main
- **Issue Tracker:** https://github.com/rakshas-oss/YuKKi-OS/issues
- **Discussions:** https://github.com/rakshas-oss/YuKKi-OS/discussions

---

**Last Updated:** August 8, 2026  
**Status:** Stable Release  
**Maintenance:** Active
