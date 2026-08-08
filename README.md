# YuKKi OS v6.4.1 — Interim-Crypt Edition

**Release Date:** August 8, 2026  
**Repository:** `rakshas-oss/YuKKi-OS`  
**Branch:** `yukki-v6.4.1-interim-crypt`  
**License:** GNU General Public License v3.0 (GPL-3.0)  
**Architect:** Aditya Muralidhar (Rakshas International Unlimited)

YuKKi OS v6.4.1 **Interim-Crypt Edition** represents the next evolutionary step in spatiotemporal weaving architecture. This release introduces **uncloneable encryption bindings**, refined Lorenz attr[...]

---

## ✨ Key Features

### 🔐 Uncloneable Encryption (NEW)
- **Clifford/Pauli Binding Simulation** - Information-theoretic quantum-inspired encryption at the bit level
- **X-Z Anti-commuting Cross-Check** - Ensures uncloneable payload properties through Pauli basis manipulation
- **Secure Slab Descriptor** - Quantum-safe payload wrapping with active basis tracking

### 🌀 6D Lorenz-Weave Engine
- **Spatiotemporal Frame Generation** - Real-time chaos-driven tensor packet generation
- **88-Byte Hyper-Aligned Packets** - Binary-compatible tensor frames with strict memory alignment
- **6D Velocity Drift** - Coupled spatial coordinates (x,y,z) with velocity vectors (u,v,w)
- **Fluidity Metric** - Sigmoid-normalized flow coherence calculation
- **Runtime Lorenz Configurability (v6.4.1)** - Parameters and initial state can be configured dynamically at startup

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
└── chaos_weave.c        ← Lorenz engine + Pauli binding core
```

**Key Components:**
- **SpatiotemporalFrame** - 88-byte packed struct (seq_id, spatial/velocity coords, fluidity, drag, payload)
- **UncloneableQuantumSlab** - Quantum descriptor with Pauli signature
- **unclonable_clifford_bind()** - XOR-based Pauli binding with 0xA5 seed
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
| **Encrypted Payload** | 16 bytes (Pauli-bound) |
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

**Expected Output:**
```
[NETWORK] Bootstrap Server active at: ws://127.0.0.1:7000
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

**Expected Output:**
```
[CORE] Open-Source Host Activated | UUID: <unique-id>
[CORE] JSON Control Channel: 127.0.0.1:8001
[CORE] Binary Tensor Channel: 127.0.0.1:9001
[C2] Fleet registry synchronized. 3 nodes online.
```

### 3. Interactive Commands

#### View Fleet
```bash
YuKKiOS_6.4 > fleet
--- Current Active Fleet Topology ---
  Node: <uuid-1> | P2P: 8001 | BINARY: 9001 (Self Node)
  Node: <uuid-2> | P2P: 8002 | BINARY: 9002
  Node: <uuid-3> | P2P: 8003 | BINARY: 9003
```

#### Send Message to Peer
```bash
YuKKiOS_6.4 > msg <uuid-2> Hello from Node 1!
[P2P INBOUND] (From <uuid-1>): Hello from Node 1!
```

#### List Remote Directory
```bash
YuKKiOS_6.4 > ls <uuid-2> /tmp
[P2P BROWSE] Directory listing from <uuid-2>:
[FILE] example.txt (512 bytes)
[DIR] subdirectory
```

#### Pull File from Peer
```bash
YuKKiOS_6.4 > get <uuid-2> /tmp/example.txt ./local_copy.txt
[P2P FILE] Streaming 512 bytes...
[P2P FILE] Transfer complete.
```

#### Establish Binary Weave Stream
```bash
YuKKiOS_6.4 > weave <uuid-3>
[STREAM] Launching 6D Weave session (Binary Mode)...
[WEAVE BINARY] Frame #0 | Spatial: [0.10, 0.00, 0.00] Drift: [0.01, 0.00, 0.00] Fluidity: 0.5000
[WEAVE BINARY] Frame #1 | Spatial: [0.25, 0.15, -0.05] Drift: [0.03, 0.04, -0.01] Fluidity: 0.5120
...
[STREAM] Toroidal weave sequence closed smoothly.
```

---

## 📁 Project Structure

```
yukki-v6.4.1-interim-crypt/
├── Cargo.toml                   # Project manifest & dependencies
├── Cargo.lock                   # Locked dependency versions
├── build.rs                     # C compiler integration (cc crate)
├── vault_license.txt            # GPL-3 license text
├── README.md                    # This file
│
├── src/
│   ├── main.rs                  # Rust async runtime & CLI shell
│   └── ffi/
│       ├── laminar_api.h        # C header for tensor packets
│       └── chaos_weave.c        # Lorenz engine + encryption
│
└── target/
    ├── debug/                   # Debug builds
    └── release/
        └── yukkios_6_4_interim  # Final optimized binary
```

---

## 🔧 Dependencies

### Rust Crates (Cargo.toml)
- **tokio** (1.x) - Async runtime with full feature set
- **tokio-tungstenite** (0.20) - WebSocket protocol implementation
- **futures-util** (0.3) - Future combinators (StreamExt, SinkExt)
- **serde** (1.0) - Serialization framework with derive macros
- **serde_json** (1.0) - JSON encoder/decoder
- **uuid** (1.6) - UUID v4 generation with serde support

### Build Dependencies
- **cc** (1.0) - C compiler invocation wrapper for build.rs

### System Dependencies
- **C99 compiler** (gcc/clang/LLVM)
- **libc** (standard C library)

---

## ⚙️ Configuration & Environment

### Legacy Mode Static Build
```bash
export LEGACY_MODE=1
cargo build --release --target=x86_64-unknown-linux-musl
```

When `LEGACY_MODE=1`, the build script automatically cross-compiles with MUSL libc for maximum portability.

### Local Transfer Directory
Files pulled via `get` command are stored in:
```
./yukkios_transfers/
```

This directory is auto-created on first P2P listener startup.

### Runtime Lorenz Configuration
The Lorenz engine keeps evolving state on every frame and now accepts runtime configuration through environment variables:

- `YUKKI_LORENZ_SIGMA`
- `YUKKI_LORENZ_RHO`
- `YUKKI_LORENZ_BETA`
- `YUKKI_LORENZ_X0`
- `YUKKI_LORENZ_Y0`
- `YUKKI_LORENZ_Z0`

If unset (or invalid), the engine preserves legacy defaults (`σ=10.0`, `ρ=28.0`, `β≈8.33333333333`, `x0=0.1`, `y0=0.0`, `z0=0.0`).

---

## 🔐 Security & Cryptography Notes

### Uncloneable Encryption Model
The Pauli binding system in `chaos_weave.c` implements **information-theoretic uncloneable payload encoding**:

1. **Message XOR** - Raw bytes XOR'd with 0xA5 seed
2. **Pauli Signature** - 16-byte payload transformed into Pauli basis signature
3. **Active Basis Tracking** - 0x3 (X-Z) ensures anti-commuting properties
4. **Handle Identifier** - Quantum slab handle (0xAE509001) marks encryption state

This is **not cryptographically certified** but demonstrates information-theoretic principles for distributed computing contexts.

### Binary Frame Integrity
- All tensor frames use strict alignment (8-byte boundaries)
- Sequence counters prevent replay attacks
- Fluidity metric acts as temporal coherence validator

---

## ⚠️ Known Limitations & Considerations

1. **Single-Machine Only** - Current implementation binds to localhost (127.0.0.1). For distributed deployment, modify `run_p2p_listener()` and `run_binary_listener()` to bind on external interfaces.

2. **No Persistent Storage** - Fleet registry is in-memory only. Nodes must re-register on bootstrap server restart.

3. **No TLS/Authentication** - WebSocket and P2P channels are unencrypted. For production, wrap with TLS/mTLS.

4. **Blocking I/O in Shell** - Interactive shell uses blocking `read_line()`. High-frequency commands may experience latency.

5. **NaN/Inf Fallback** - Lorenz engine resets state on numerical overflow. Mathematical stability guaranteed but trajectory continuity may be disrupted.

6. **Linux/Unix Only** - Zsh script and build pipeline target POSIX systems. Windows support requires WSL2 or native Rust port.

---

## 📚 References & Related Work

- **Lorenz System** - Deterministic chaos generator (https://en.wikipedia.org/wiki/Lorenz_system)
- **Pauli Matrices** - Quantum gate algebra (https://en.wikipedia.org/wiki/Pauli_matrices)
- **Tokio Async Runtime** - https://tokio.rs/
- **WebSocket Protocol (RFC 6455)** - https://tools.ietf.org/html/rfc6455

---

## 📜 License

**GNU General Public License v3.0 (GPL-3.0)**

This operating system suite is distributed under the GPL-3.0 license. You are free to:
- **Use** the software for any purpose
- **Modify** the source code
- **Distribute** copies and modifications

Under the condition that:
- All derivative works remain under GPL-3.0
- Original copyright and license notices are preserved
- Source code modifications are documented

See `vault_license.txt` for the complete GPL-3.0 legal text.

---

## 👤 Authors & Contributors

**Primary Architect:** Aditya Muralidhar  
**Organization:** Rakshas International Unlimited  
**Repository:** https://github.com/rakshas-oss/YuKKi-OS

---

## 🔗 Quick Links

- **Latest Release:** https://github.com/rakshas-oss/YuKKi-OS/tree/yukki-v6.4.1-interim-crypt
- **Issue Tracker:** https://github.com/rakshas-oss/YuKKi-OS/issues
- **Discussions:** https://github.com/rakshas-oss/YuKKi-OS/discussions

---

**Last Updated:** August 8, 2026  
**Status:** Stable Release  
**Maintenance:** Active
