# YuKKi OS 6.0.0-beta (Hyper-Fluid Edition)

YuKKi OS is a Linux-based peer-to-peer application framework with dependency-aware remote build execution concepts for Internet 3. This repository tracks the evolution of the platform from the shell-based YuKKi OS 4 series to the new Rust/C-based hyper-fluid mesh of v6.

## Repository Layout

| File | Description |
|---|---|
| `LICENSE` | GNU General Public License v3.0 (GPL-3). |
| `README.md` | This file. |
| `YuKKi OS 4.sh` | The YuKKi OS 4 shell-based environment. |
| `YuKKi OS 6 Open Source Installer.txt` | Open-source genesis installer for YuKKi OS 6.0.0-beta. |

## What's New in YuKKi OS 6

YuKKi OS 6 refits the project around a zero-drag, 6D spatiotemporal Lorenz-weave mesh:

1. **Hyper-Aligned 6D Tensor Packets**
   - 88-byte `SpatiotemporalFrame` aligned to 8-byte boundaries.
   - Combines spatial coordinates (`x`, `y`, `z`) with temporal drift (`u`, `v`, `w`) plus fluidity/drag telemetry.

2. **Lorenz Attractor Chaos Engine (C Core)**
   - Real-time chaotic manifold stepping through a C library (`chaos_weave.c`).
   - Numeric guard rails prevent floating-point explosion.

3. **Rust System Engine with FFI Bridge**
   - `main.rs` wraps the chaos engine, exposes a WebSocket bootstrap/fleet coordinator, and drives framed TCP P2P channels.
   - Length-prefixed TCP framing keeps the byte stream unambiguous.

4. **P2P Mesh Commands**
   - `fleet` / `peers` — display current registry topology.
   - `msg <UUID> <text>` — send plain messages to a fleet node.
   - `weave <UUID>` — stream 6D weave frames to a selected peer.
   - `exit` / `quit` — shut down the node CLI.

5. **Open Source Genesis Installer**
   - `YuKKi OS 6 Open Source Installer.txt` is a self-contained bash generator.
   - It emits the full Cargo workspace, C sources, build script, and GPL-3 license notice, then compiles the release binary.

## Quick Start

1. Run the installer:
   ```bash
   bash "YuKKi OS 6 Open Source Installer.txt"
   ```
   This creates the `yukkios_6_fluid/` project and builds `./yukkios_6_fluid/target/release/yukkios_6_sovereign`.

2. Launch the bootstrap server:
   ```bash
   ./yukkios_6_fluid/target/release/yukkios_6_sovereign bootstrap 127.0.0.1:8080
   ```

3. Start two nodes:
   ```bash
   ./yukkios_6_fluid/target/release/yukkios_6_sovereign node 127.0.0.1:8080 9110
   ./yukkios_6_fluid/target/release/yukkios_6_sovereign node 127.0.0.1:8080 9120
   ```

4. In a node CLI, run `fleet` to list peers and then:
   ```
   weave <TARGET_PEER_UUID>
   ```

## Version History

- **YuKKi OS 4** — Distributed build manifest exchange (`manifest submit` / `manifest get`), configurable linenoise visual prompt, CRTC/PIPEDA compliance logging.
- **YuKKi OS 6.0.0-beta** — Re-foundation around a Rust/C FFI chaos mesh, 6D spatiotemporal frame streaming, and framed P2P networking.

## License

This project is licensed under the GNU General Public License v3.0. See `LICENSE` for the full text.
