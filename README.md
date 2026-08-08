# YuKKi OS v6.4.3 — Out-of-Band Integrity Edition

**Release Date:** August 8, 2026  
**Repository:** `rakshas-oss/YuKKi-OS`  
**Branch:** `main`  
**License:** GNU General Public License v3.0 (GPL-3.0)  
**Architect:** Aditya Muralidhar (Rakshas International Unlimited)

YuKKi OS v6.4.3 **Out-of-Band Integrity Edition** extends the spatiotemporal weaving architecture with an **out-of-band rolling hash integrity workflow**, **60-frame sync trigger**, and **node quarantine/blacklist** enforcement — while preserving the ChaCha20 payload binding path, Lorenz-driven tensor model, and distributed P2P runtime behavior introduced in v6.4.2.

---

## ✨ Key Features

### 🛡️ OOB Rolling Hash Integrity (NEW in v6.4.3)
- **FNV-1a Rolling Hash Accumulator** — `oob_fnv1a_rolling_hash()` maintains a per-stream integrity fingerprint across all frames. Implemented as an FNV-1a 64-bit derivative; see security notes below.
- **60-Frame Sync Trigger** — `oob_sync_check(seq)` fires at every 60-frame boundary (`seq % 60 == 0`), signalling the runtime to broadcast the current rolling hash to peers for cross-node integrity comparison.
- **Node Quarantine / Blacklist** — `oob_quarantine_node(uuid)` registers a peer UUID as quarantined. Quarantined nodes are denied `weave` sessions and excluded from OOB sync participation. Up to 64 nodes may be blacklisted simultaneously.
- **Shell Commands** — `quarantine <uuid>` and `quarantine_check <uuid>` allow operators to manage the quarantine table interactively.

### 🔐 ChaCha20 Payload Binding (from v6.4.2 — retained)
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
- `weave <uuid>` - Establish binary tensor stream with target node (blocked if node is quarantined)
- `quarantine <uuid>` - Add node to OOB quarantine/blacklist
- `quarantine_check <uuid>` - Check quarantine status of a node
- `exit`/`quit` - Graceful shutdown

---

## 🏗️ Architecture Overview

### Layer 1: FFI Bridge (Legacy-Safe C99)
```
src/ffi/
├── laminar_api.h        ← Binary tensor packet definitions + OOB integrity API declarations
└── chaos_weave.c        ← Lorenz engine + ChaCha20 payload binding + OOB integrity engine
```

**Key Components:**
- **SpatiotemporalFrame** - 88-byte packed struct (seq_id, spatial/velocity coords, fluidity, drag, payload)
- **SecureQuantumSlab** - Descriptor with encrypted signature and active basis flag
- **chacha20_block()** - Keystream generator using constant-time ARX quarter-round composition
- **secure_chacha20_bind()** - 16-byte payload binding via XOR against generated keystream bytes
- **generate_lorenz_step()** - Differential equation solver with numerical stability safeguards
- **oob_fnv1a_rolling_hash()** - FNV-1a 64-bit rolling hash for stream integrity (non-cryptographic)
- **oob_integrity_update()** - Per-frame rolling hash accumulation
- **oob_sync_check()** - 60-frame OOB sync boundary detection
- **oob_quarantine_node() / oob_is_quarantined()** - Node blacklist management

### Layer 2: Rust Async Runtime
```
src/main.rs
├── ChaosController          ← FFI frame extraction wrapper
├── oob_update()             ← OOB rolling hash feed per-frame
├── oob_is_sync_boundary()   ← 60-frame sync trigger check
├── quarantine_node()        ← Quarantine a peer node UUID
├── is_node_quarantined()    ← Query quarantine status
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
| **OOB Sync Period** | Every 60 frames |
| **Quarantine Table** | Up to 64 node UUIDs |
| **OOB Hash Algorithm** | FNV-1a 64-bit derivative (non-cryptographic) |

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

### Genesis Script (v6.4.3 OOB-Integrity Edition)
```bash
zsh ./YuKKi_OS_6.4.3_OOB-Integrity.sh
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
- `quarantine <uuid>` — add node to blacklist
- `quarantine_check <uuid>` — query quarantine status
- `exit` / `quit`

---

## 🔐 Security & Cryptography Notes

### OOB Rolling Hash Integrity (v6.4.3)
The `oob_fnv1a_rolling_hash()` function in `src/ffi/chaos_weave.c` is an FNV-1a 64-bit derivative used for lightweight, non-adversarial stream integrity verification:

1. **FNV-1a Accumulation** — Each byte XORs with the hash state, then multiplies by the FNV-1a prime (1099511628211)
2. **Sequence Ordering** — The 64-bit `seq_id` is mixed in first, making the hash order-sensitive
3. **60-Frame Sync** — `oob_sync_check(seq)` returns `1` at every 60th frame; the runtime logs a snapshot trigger

> ⚠️ **Security Disclaimer:** The OOB hash is an FNV-1a derivative and is **NOT** a BLAKE3 or cryptographic MAC. It provides no adversarial tamper-detection guarantee and should not be relied upon for security-critical integrity checks. Use a proper authenticated channel or HMAC for adversarial scenarios.

### Node Quarantine / Blacklist
Quarantined node UUIDs are stored in a static C-level table (`g_quarantine_table`). The table is in-process only; it does not persist across restarts. Maximum capacity is 64 entries.

> ⚠️ **Limitation:** The quarantine table is process-local and is not broadcast to peers. Coordinated quarantine requires an out-of-band signalling mechanism.

### ChaCha20 Binding Model (from v6.4.2 — retained)
The payload binding path in `src/ffi/chaos_weave.c` uses a ChaCha20-style keystream workflow:

1. **State Setup** - Sigma constants + 256-bit mesh key + sequence-derived nonce
2. **20-Round Mixing** - Column and diagonal quarter-round cycles
3. **Keystream Finalization** - Working state folded back into initial state
4. **Payload Binding** - First 16 keystream bytes XOR against payload

> ⚠️ **Hardcoded Key Note:** The mesh key used in ChaCha20 binding is hardcoded for demonstration. Production deployments should inject keys via a secure provisioning path.

### laminar_api.h Portability
The packed struct `SpatiotemporalFrame` now uses a portability macro (`LAMINAR_PACKED_ALIGNED`) that resolves to `__attribute__((packed, aligned(8)))` on GCC/Clang and `__declspec(align(8))` on MSVC, with `#pragma pack(push, 1)` for cross-compiler field ordering.

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
**Status:** Stable Release — v6.4.3 Out-of-Band Integrity Edition  
**Maintenance:** Active
